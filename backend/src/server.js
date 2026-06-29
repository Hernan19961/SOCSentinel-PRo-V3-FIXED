import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import http from 'http';
import { Server } from 'socket.io';
import { pool } from './db/pool.js';
import { normalize, analyzeEvent } from './services/rules.js';
import { runCorrelation } from './services/correlation.js';
import { execFile } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '../..');
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors:{ origin:'*' }});
app.use(cors()); app.use(express.json({limit:'10mb'}));
app.get('/api/health', (_,res)=>res.json({ok:true, name:'SOCSentinel Pro V3', mode:'real-time-ready', responseActions: process.env.ALLOW_RESPONSE_ACTIONS === 'true'}));
app.get('/api/local-assets', (_,res)=>res.json({
  hostname: localAssetCache.hostname,
  localIps: trustedLocalIps(),
  interfaces: localAssetCache.interfaces,
  refreshedAt: localAssetCache.refreshedAt
}));
const seenFirewallLines = new Set();
let lastFirewallError = '';
const dataDir = path.join(projectRoot, 'backend', 'data');
const defenderDismissedPath = path.join(dataDir, 'defender-dismissed.json');
let localAssetCache = {hostname: os.hostname(), ips: [], interfaces: {}, refreshedAt: null};
let correlationTimer = null;
let correlationRunning = false;

const riskyAttachmentExt = ['.exe','.scr','.bat','.cmd','.ps1','.vbs','.js','.jse','.wsf','.hta','.iso','.img','.lnk','.docm','.xlsm','.zip','.rar','.7z','.html','.htm'];
const shortenerDomains = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','cutt.ly','rebrand.ly','lnkd.in'];
const brandNames = ['microsoft','office','outlook','onedrive','google','gmail','paypal','amazon','apple','netflix','banco','bank','dhl','fedex','github','facebook','instagram'];

function normalizeHeaders(raw){
  return String(raw || '').replace(/\r?\n[ \t]+/g, ' ');
}

function getHeader(raw, name){
  const match = normalizeHeaders(raw).match(new RegExp(`^${name}:\\s*(.+)$`, 'im'));
  return match ? match[1].trim() : '';
}

function getHeaders(raw, name){
  return [...normalizeHeaders(raw).matchAll(new RegExp(`^${name}:\\s*(.+)$`, 'gim'))].map((m)=>m[1].trim());
}

function domainFromEmail(email){
  const match = String(email || '').toLowerCase().match(/@([^>\s]+)/);
  return match ? match[1].replace(/[>.,;]+$/,'') : '';
}

function extractEmailAddress(value){
  const match = String(value || '').match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return match ? match[0].toLowerCase() : String(value || '').trim();
}

function extractUrls(text){
  return [...String(text || '').matchAll(/https?:\/\/[^\s<>"')]+/gi)].map((m)=>m[0].replace(/[.,;:]+$/,''));
}

function hostnameFromUrl(url){
  try { return new URL(url).hostname.toLowerCase().replace(/^www\./,''); } catch { return ''; }
}

function extractAttachments(raw){
  const names = [...String(raw || '').matchAll(/filename\*?=(?:UTF-8''|")?([^"\r\n;]+)/gi)].map((m)=>decodeURIComponent(String(m[1]).replace(/"/g,'').trim()));
  const dispositions = [...String(raw || '').matchAll(/name="([^"]+)"/gi)].map((m)=>m[1].trim());
  return [...new Set([...names, ...dispositions])].filter(Boolean);
}

function analyzeEmailThreat(rawEmail){
  const senderHeader = getHeader(rawEmail, 'From');
  const replyToHeader = getHeader(rawEmail, 'Reply-To');
  const returnPathHeader = getHeader(rawEmail, 'Return-Path');
  const recipientHeader = getHeader(rawEmail, 'To');
  const subject = getHeader(rawEmail, 'Subject') || '(sin asunto)';
  const authResults = [...getHeaders(rawEmail, 'Authentication-Results'), ...getHeaders(rawEmail, 'ARC-Authentication-Results'), getHeader(rawEmail, 'Received-SPF')].filter(Boolean).join(' | ');
  const sender = extractEmailAddress(senderHeader);
  const replyTo = extractEmailAddress(replyToHeader);
  const returnPath = extractEmailAddress(returnPathHeader);
  const recipient = extractEmailAddress(recipientHeader);
  const senderDomain = domainFromEmail(sender);
  const returnPathDomain = domainFromEmail(returnPath);
  const urls = extractUrls(rawEmail).map((url)=>({url, domain:hostnameFromUrl(url)}));
  const attachments = extractAttachments(rawEmail).map((name)=>({name, risky:riskyAttachmentExt.some((ext)=>name.toLowerCase().endsWith(ext))}));
  const lower = String(rawEmail || '').toLowerCase();
  const indicators = [];
  let score = 0;

  if(replyTo && sender && replyTo !== sender){ score += 15; indicators.push(`Reply-To distinto del remitente: ${replyTo}`); }
  if(returnPath && senderDomain && returnPathDomain && senderDomain !== returnPathDomain){ score += 15; indicators.push(`Return-Path no coincide con From: ${returnPath}`); }
  if(/spf=(fail|softfail|neutral|temperror|permerror)|dkim=(fail|neutral|temperror|permerror)|dmarc=(fail|temperror|permerror)/i.test(authResults)){ score += 30; indicators.push('SPF/DKIM/DMARC fallido o debil'); }
  if(/spf=pass/i.test(authResults) && /dkim=pass/i.test(authResults) && /dmarc=pass/i.test(authResults)){ score -= 10; indicators.push('Autenticacion SPF/DKIM/DMARC valida'); }
  if(/password|contrase(?:Ã±|n)a|verifica|verify|urgent|urgente|suspend|bloquead|factura|invoice|payment|pago|cuenta|account/.test(lower)){ score += 15; indicators.push('Lenguaje de urgencia o credenciales'); }
  if(/login|signin|iniciar sesi(?:o|Ã³)n|actualizar cuenta|verify account/.test(lower)){ score += 15; indicators.push('Solicitud de inicio de sesion o verificacion'); }
  if(attachments.some((item)=>item.risky)){ score += 30; indicators.push('Adjunto con extension riesgosa'); }
  if(urls.some((item)=>shortenerDomains.includes(item.domain))){ score += 20; indicators.push('URL acortada'); }
  if(urls.some((item)=>/xn--/.test(item.domain))){ score += 20; indicators.push('Dominio punycode posible homografo'); }

  for(const item of urls){
    for(const brand of brandNames){
      if(item.domain.includes(brand) && !item.domain.endsWith(`${brand}.com`) && !item.domain.endsWith(`${brand}.cl`)){
        score += 15;
        indicators.push(`Dominio posiblemente suplantando marca: ${item.domain}`);
        break;
      }
    }
  }

  if(urls.length >= 4){ score += 10; indicators.push('Multiples enlaces en el correo'); }
  if(!sender){ score += 10; indicators.push('Remitente no identificado'); }

  const finalScore = Math.max(0, Math.min(score,100));
  const severity = finalScore >= 70 ? 'critical' : finalScore >= 40 ? 'high' : finalScore >= 20 ? 'medium' : 'low';
  const verdict = finalScore >= 70 ? 'phishing_probable' : finalScore >= 40 ? 'sospechoso' : finalScore >= 20 ? 'revisar' : 'probablemente_legitimo';
  const authVerdict = /spf=pass/i.test(authResults) && /dkim=pass/i.test(authResults) && /dmarc=pass/i.test(authResults) ? 'autenticacion fuerte' : /spf=(fail|softfail)|dkim=fail|dmarc=fail/i.test(authResults) ? 'autenticacion fallida' : 'autenticacion insuficiente';
  const recommendedAction = finalScore >= 70 ? 'Cuarentena/bloquear remitente y revisar URLs/adjuntos.' : finalScore >= 40 ? 'Revisar cabeceras, URLs y adjuntos antes de interactuar.' : 'Registrar como evidencia y monitorear.';
  return {sender, senderDomain, replyTo, returnPath, returnPathDomain, recipient, subject, authResults, score:finalScore, severity, verdict, authVerdict, recommendedAction, indicators:[...new Set(indicators)], urls, attachments};
}

function localIps(){
  return Object.values(os.networkInterfaces())
    .flat()
    .filter(Boolean)
    .map((item)=>item.address)
    .filter(Boolean);
}

function normalizeIpValue(ip){
  return String(ip || '')
    .trim()
    .toLowerCase()
    .replace(/^::ffff:/, '')
    .replace(/%.+$/, '')
    .replace(/^\[|\]$/g, '');
}

function refreshLocalAssets(){
  const interfaces = os.networkInterfaces();
  const ips = Object.values(interfaces)
    .flat()
    .filter(Boolean)
    .map((item)=>normalizeIpValue(item.address))
    .filter(Boolean);
  localAssetCache = {
    hostname: process.env.SOC_HOSTNAME || os.hostname() || process.env.COMPUTERNAME || 'SOCSentinel',
    ips: [...new Set(['127.0.0.1', '::1', ...ips])],
    interfaces,
    refreshedAt: new Date().toISOString()
  };
  return localAssetCache;
}

function trustedLocalIps(){
  if(!localAssetCache.refreshedAt) refreshLocalAssets();
  return localAssetCache.ips;
}

function isOwnDeviceIp(ip){
  const normalized = normalizeIpValue(ip);
  if(!normalized) return false;
  return normalized === '::1'
    || normalized === '127.0.0.1'
    || normalized.startsWith('fe80:')
    || trustedLocalIps().includes(normalized);
}

function isPrivateIp(ip){
  const raw = normalizeIpValue(ip);
  if(raw === '::1' || raw.startsWith('fe80:') || raw.startsWith('fc') || raw.startsWith('fd')) return true;
  const parts = raw.split('.').map(Number);
  if(parts.length !== 4 || parts.some((part)=>Number.isNaN(part))) return false;
  const [a,b] = parts;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 169 || a === 127;
}


function isLocalOrLabIp(ip){
  const raw = normalizeIpValue(ip);
  if(!raw) return true;
  if(raw === '::1' || raw === '127.0.0.1') return true;
  if(raw === '192.168.42.1' || raw === 'fd0d:edc3:e12a::1') return true;
  if(raw.startsWith('fe80:') || raw.startsWith('fd')) return true;
  const parts = raw.split('.').map(Number);
  if(parts.length !== 4 || parts.some((part)=>Number.isNaN(part))) return false;
  const [a,b] = parts;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127;
}

function isTrustedProcess(processName){
  const normalized = String(processName || '').replace(/\//g,'\\').toLowerCase();
  return ['chrome.exe','msedge.exe','svchost.exe','system','powershell.exe'].some((name)=>
    normalized === name || normalized.endsWith('\\' + name)
  );
}

function scorePortScan(row, options = {}){
  const attempts = Number(row?.attempts || 0);
  const attempts60 = Number(row?.attempts_60 || attempts);
  const uniquePorts = Number(row?.ports || row?.unique_ports || 0);
  const uniqueHosts = Number(row?.hosts || row?.unique_hosts || 0);
  const sensitivePorts = Array.isArray(row?.sensitive_ports) ? row.sensitive_ports.map(Number).filter(Boolean) : [];
  const isLocalSource = isLocalOrLabIp(row?.source_ip);
  const trustedProcess = isTrustedProcess(row?.process) && !options.forceProcessSuspicious;
  const labMode = process.env.SOC_MODE !== 'production';
  const reasons = [];
  let score = 0;

  if(attempts60 > 10){ score += 25; reasons.push(attempts60 + ' intentos en 60s'); }
  if(uniquePorts > 15){ score += 35; reasons.push(uniquePorts + ' puertos unicos en 120s'); }
  if(uniquePorts > 25){ score += 25; reasons.push('mas de 25 puertos unicos (' + uniquePorts + ')'); }
  if(uniqueHosts > 3){ score += 25; reasons.push(uniqueHosts + ' hosts destino en menos de 2 minutos'); }
  if(sensitivePorts.length){ score += 15; reasons.push('puertos sensibles tocados: ' + sensitivePorts.join(', ')); }
  if(uniquePorts <= 3 && uniqueHosts <= 1){ score -= 35; reasons.push('pocos puertos/host: trafico observado, no escaneo'); }
  if(isLocalSource){ score -= 45; reasons.push('origen local/lab allowlist'); }
  if(trustedProcess && uniquePorts <= 15 && uniqueHosts <= 3){ score -= 20; reasons.push('proceso confiable: ' + row.process); }

  score = Math.max(0, Math.min(100, score));
  if(labMode && score >= 90 && (isLocalSource || (uniquePorts < 50 && uniqueHosts < 5))){
    score = 89;
    reasons.push('modo lab/demo: critico reservado para patron claramente malicioso');
  }
  const severity = score >= 90 ? 'critical' : score >= 75 ? 'high' : score >= 60 ? 'medium' : score >= 40 ? 'low' : 'info';
  return {score, severity, shouldAlert:score >= 40, reasons};
}

function readJsonFile(filePath, fallback){
  try {
    if(!fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJsonFile(filePath, value){
  fs.mkdirSync(path.dirname(filePath), {recursive:true});
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function defenderDetectionKey(item){
  const resources = Array.isArray(item?.resources) ? item.resources.join('|') : '';
  return `${item?.threatId || 'unknown'}:${stableHash(`${item?.processName || ''}:${resources}`)}`;
}

function filterDismissedDefenderDetections(status){
  if(!status?.ok || !Array.isArray(status.detections)) return status;
  const dismissed = readJsonFile(defenderDismissedPath, {keys:[]});
  const keys = new Set(Array.isArray(dismissed.keys) ? dismissed.keys : []);
  const originalCount = status.detections.length;
  const detections = status.detections.filter((item)=>item.actionSuccess === false || !keys.has(defenderDetectionKey(item)));
  const activeThreats = detections.filter((item)=>item.actionSuccess === false).length;
  return {
    ...status,
    detections,
    summary: {
      ...status.summary,
      activeThreats,
      totalDetections: detections.length,
      hiddenHandledDetections: Math.max(0, originalCount - detections.length)
    }
  };
}

function stableHash(value){
  return String(value || '').split('').reduce((acc, char)=>((acc << 5) - acc + char.charCodeAt(0)) >>> 0, 2166136261);
}

const geoSeeds = [
  {country:'United States', city:'Ashburn', latitude:39.0438, longitude:-77.4874, asn:'AS-US-External'},
  {country:'Brazil', city:'Sao Paulo', latitude:-23.5505, longitude:-46.6333, asn:'AS-BR-External'},
  {country:'Germany', city:'Frankfurt', latitude:50.1109, longitude:8.6821, asn:'AS-DE-External'},
  {country:'Netherlands', city:'Amsterdam', latitude:52.3676, longitude:4.9041, asn:'AS-NL-External'},
  {country:'United Kingdom', city:'London', latitude:51.5072, longitude:-0.1276, asn:'AS-UK-External'},
  {country:'France', city:'Paris', latitude:48.8566, longitude:2.3522, asn:'AS-FR-External'},
  {country:'Chile', city:'Santiago', latitude:-33.4489, longitude:-70.6693, asn:'AS-CL-Local'},
  {country:'Japan', city:'Tokyo', latitude:35.6762, longitude:139.6503, asn:'AS-JP-External'},
  {country:'Singapore', city:'Singapore', latitude:1.3521, longitude:103.8198, asn:'AS-SG-External'},
  {country:'India', city:'Mumbai', latitude:19.076, longitude:72.8777, asn:'AS-IN-External'}
];

function localGeoIntel(ip){
  if(isPrivateIp(ip)){
    return {
      ip,
      country:'Local/Lab',
      city:'Red local',
      latitude:-33.4489,
      longitude:-70.6693,
      asn:'RFC1918',
      isp:'LAN / laboratorio',
      reputation_score:0,
      abuse_confidence:null,
      total_reports:null,
      source:'local'
    };
  }
  const seed = geoSeeds[stableHash(ip) % geoSeeds.length];
  return {
    ip,
    ...seed,
    isp:'Proveedor externo no verificado',
    reputation_score:0,
    abuse_confidence:null,
    total_reports:null,
    source:'estimated'
  };
}

async function getIpIntel(ip){
  if(!ip) return null;
  const cached = await pool.query("SELECT * FROM ip_intel WHERE ip=$1 AND updated_at > now() - interval '12 hours'", [ip]).catch(()=>({rowCount:0, rows:[]}));
  if(cached.rowCount) return cached.rows[0];
  let intel = localGeoIntel(ip);
  if(process.env.ABUSEIPDB_API_KEY && !isPrivateIp(ip)){
    try {
      const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
      const response = await fetch(url, {headers:{Key:process.env.ABUSEIPDB_API_KEY, Accept:'application/json'}, signal:AbortSignal.timeout(6000)});
      if(response.ok){
        const json = await response.json();
        const data = json.data || {};
        intel = {
          ip,
          country:data.countryCode || intel.country,
          city:intel.city,
          latitude:intel.latitude,
          longitude:intel.longitude,
          asn:data.asn ? `AS${data.asn}` : intel.asn,
          isp:data.isp || data.domain || intel.isp,
          reputation_score:Number(data.abuseConfidenceScore || 0),
          abuse_confidence:Number(data.abuseConfidenceScore || 0),
          total_reports:Number(data.totalReports || 0),
          source:'abuseipdb',
          raw:data
        };
      }
    } catch {
      intel = {...intel, source:'estimated'};
    }
  }
  await pool.query(
    `INSERT INTO ip_intel(ip,country,city,latitude,longitude,asn,isp,reputation_score,abuse_confidence,total_reports,source,raw,updated_at)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())
     ON CONFLICT(ip) DO UPDATE SET country=EXCLUDED.country, city=EXCLUDED.city, latitude=EXCLUDED.latitude, longitude=EXCLUDED.longitude, asn=EXCLUDED.asn, isp=EXCLUDED.isp, reputation_score=EXCLUDED.reputation_score, abuse_confidence=EXCLUDED.abuse_confidence, total_reports=EXCLUDED.total_reports, source=EXCLUDED.source, raw=EXCLUDED.raw, updated_at=now()
     RETURNING *`,
    [intel.ip,intel.country,intel.city,intel.latitude,intel.longitude,intel.asn,intel.isp,intel.reputation_score,intel.abuse_confidence,intel.total_reports,intel.source,JSON.stringify(intel.raw || intel)]
  ).catch(()=>{});
  return intel;
}

async function buildTimeline({ip, alertId, minutes = 30}){
  let sourceIp = ip || '';
  let alert = null;
  if(alertId){
    const r = await pool.query('SELECT * FROM alerts WHERE id=$1', [alertId]);
    alert = r.rows[0] || null;
    sourceIp = sourceIp || alert?.source_ip || '';
  }
  const values = [];
  let where = '';
  if(sourceIp){
    values.push(sourceIp);
    where = `WHERE (source_ip=$1 OR raw::text ILIKE '%' || $1 || '%')`;
  } else if(alert?.hostname){
    values.push(alert.hostname);
    where = `WHERE hostname=$1`;
  }
  const eventWhere = where ? `${where} AND created_at > now() - ($${values.length + 1}::int || ' minutes')::interval` : `WHERE created_at > now() - ($${values.length + 1}::int || ' minutes')::interval`;
  const events = await pool.query(
    `SELECT 'event' AS kind, id, event_id::text AS code, provider AS title, severity_placeholder.severity, hostname, username, process, source_ip, destination_port, file_path, raw, created_at
     FROM events
     CROSS JOIN (SELECT 'info'::text AS severity) severity_placeholder
     ${eventWhere}
     ORDER BY created_at DESC
     LIMIT 120`,
    [...values, minutes]
  );
  const alertValues = sourceIp ? [sourceIp, minutes] : [minutes];
  const alertWhere = sourceIp ? `WHERE (source_ip=$1 OR evidence::text ILIKE '%' || $1 || '%') AND created_at > now() - ($2::int || ' minutes')::interval` : `WHERE created_at > now() - ($1::int || ' minutes')::interval`;
  const alerts = await pool.query(
    `SELECT 'alert' AS kind, id, NULL AS code, title, severity, hostname, username, process, source_ip, NULL::int AS destination_port, file_path, evidence AS raw, created_at
     FROM alerts
     ${alertWhere}
     ORDER BY created_at DESC
     LIMIT 80`,
    alertValues
  );
  return [...events.rows, ...alerts.rows].sort((a,b)=>new Date(b.created_at) - new Date(a.created_at));
}

async function generateIncidentReport({target, alertId}){
  const reportsDir = path.join(projectRoot, 'reports');
  fs.mkdirSync(reportsDir, {recursive:true});
  let alert = null;
  if(alertId){
    const r = await pool.query('SELECT * FROM alerts WHERE id=$1', [alertId]);
    alert = r.rows[0] || null;
  }
  const ip = target || alert?.source_ip || '';
  const intel = ip ? await getIpIntel(ip) : null;
  const timeline = await buildTimeline({ip, alertId, minutes:240});
  const safeName = `${new Date().toISOString().replace(/[:.]/g,'-')}-${(ip || alertId || 'incident').replace(/[^a-zA-Z0-9.-]/g,'_')}.md`;
  const reportPath = path.join(reportsDir, safeName);
  const htmlPath = reportPath.replace(/\.md$/i, '.html');
  const lines = [
    '# SOCSentinel Incident Report',
    '',
    `Generated: ${new Date().toISOString()}`,
    `Target: ${ip || target || 'N/A'}`,
    '',
    '## Alert',
    alert ? `- ${alert.severity?.toUpperCase() || 'INFO'}: ${alert.title}` : '- Manual report',
    alert ? `- Host: ${alert.hostname || 'N/A'}` : '',
    alert ? `- User: ${alert.username || 'N/A'}` : '',
    alert ? `- Process: ${alert.process || 'N/A'}` : '',
    alert ? `- MITRE: ${alert.mitre || 'N/A'}` : '',
    '',
    '## IP Intelligence',
    intel ? `- Location: ${intel.city || 'N/A'}, ${intel.country || 'N/A'}` : '- No IP intel',
    intel ? `- ASN/ISP: ${intel.asn || 'N/A'} / ${intel.isp || 'N/A'}` : '',
    intel ? `- Reputation: ${intel.reputation_score ?? 0} (${intel.source || 'local'})` : '',
    '',
    '## Timeline',
    ...timeline.slice(0, 80).map((item)=>`- ${new Date(item.created_at).toISOString()} [${item.kind}] ${item.title || item.provider || item.event_id} host=${item.hostname || '-'} user=${item.username || '-'} process=${item.process || '-'} ip=${item.source_ip || '-'} port=${item.destination_port || '-'}`),
    '',
    '## Recommended Response',
    '- Confirmar si la IP/proceso corresponde a actividad autorizada.',
    '- Bloquear IP o puerto solo si el origen no es confiable.',
    '- Ejecutar Microsoft Defender y revisar evidencia antes de remediar.',
    '- Mantener este reporte como evidencia de investigacion.'
  ].filter((line)=>line !== '');
  fs.writeFileSync(reportPath, lines.join('\n'), 'utf8');
  const html = `<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>SOCSentinel Incident Report</title>
  <style>
    body{font-family:Segoe UI,Arial,sans-serif;background:#f6f8fb;color:#111827;margin:40px}
    main{background:#fff;border:1px solid #d8dee9;border-radius:10px;max-width:980px;margin:auto;padding:34px}
    h1{margin-top:0;color:#0f172a} h2{border-bottom:1px solid #e5e7eb;padding-bottom:6px}
    li{margin:7px 0}.meta{color:#475569}.sev{color:#b91c1c;font-weight:700}
    @media print{body{background:#fff;margin:0}main{border:0}}
  </style>
</head>
<body><main>${lines.map((line)=>{
    if(line.startsWith('# ')) return `<h1>${line.slice(2)}</h1>`;
    if(line.startsWith('## ')) return `<h2>${line.slice(3)}</h2>`;
    if(line.startsWith('- ')) return `<li>${line.slice(2)}</li>`;
    if(!line) return '';
    return `<p class="meta">${line}</p>`;
  }).join('\n')}</main></body></html>`;
  fs.writeFileSync(htmlPath, html, 'utf8');
  return `${reportPath}\nReporte imprimible/PDF-ready: ${htmlPath}`;
}

async function hasRecentDuplicateAlert(alert){
  const result = await pool.query(
    `SELECT id FROM alerts
     WHERE title=$1
       AND coalesce(hostname,'')=coalesce($2,'')
       AND coalesce(username,'')=coalesce($3,'')
       AND coalesce(process,'')=coalesce($4,'')
       AND coalesce(source_ip,'')=coalesce($5,'')
       AND created_at > now() - interval '10 minutes'
     LIMIT 1`,
    [alert.title, alert.hostname || '', alert.username || '', alert.process || '', alert.sourceIp || '']
  );
  return result.rowCount > 0;
}

function parseFirewallLine(line){
  const parts = String(line || '').trim().split(/\s+/);
  if(parts.length < 17 || parts[0].startsWith('#')) return null;
  const [date,time,action,protocol,sourceIp,destinationIp,sourcePort,destinationPort,size,tcpFlags,tcpSyn,tcpAck,tcpWin,icmpType,icmpCode,info,pathValue] = parts;
  if(!sourceIp || !destinationIp || !destinationPort) return null;
  return {
    eventId: 9001,
    provider: 'Windows Firewall',
    hostname: process.env.COMPUTERNAME || 'unknown',
    timestamp: `${date}T${time}`,
    sourceIp,
    destinationIp,
    sourcePort: Number(sourcePort) || null,
    destinationPort: Number(destinationPort) || null,
    protocol,
    action,
    rawMessage: line,
    raw: {date,time,action,protocol,sourceIp,destinationIp,sourcePort,destinationPort,size,tcpFlags,tcpSyn,tcpAck,tcpWin,icmpType,icmpCode,info,path:pathValue}
  };
}

const sensitiveScanPorts = [21,22,23,25,53,80,135,139,443,445,1433,3306,3389,5432,5900,5985,5986,8080,8443];
const noisyScanPorts = [137,138,1900,5353];

async function detectImmediatePortScan(event){
  if(!event.sourceIp || !event.destinationPort) return null;
  if(noisyScanPorts.includes(Number(event.destinationPort))) return null;
  if(isOwnDeviceIp(event.sourceIp)) return null;
  const blocked = await pool.query("SELECT ip FROM blocked_ips WHERE status='blocked' AND ip=$1", [event.sourceIp]);
  if(blocked.rowCount) return null;
  const duplicate = await pool.query(
    `SELECT id FROM alerts WHERE title='Posible escaneo de puertos' AND source_ip=$1 AND created_at > now() - interval '5 minutes' LIMIT 1`,
    [event.sourceIp]
  );
  if(duplicate.rowCount) return null;
  const r = await pool.query(
    `SELECT
       count(*)::int AS attempts,
       count(*) FILTER (WHERE created_at > now() - interval '60 seconds')::int AS attempts_60,
       count(DISTINCT destination_port)::int AS ports,
       count(DISTINCT destination_ip)::int AS hosts,
       max(process) AS process,
       array_agg(DISTINCT destination_port ORDER BY destination_port) FILTER (WHERE destination_port IS NOT NULL) AS port_list,
       array_agg(DISTINCT destination_port ORDER BY destination_port) FILTER (WHERE destination_port = ANY($2::int[])) AS sensitive_ports,
       max(created_at) AS last_seen,
       min(created_at) AS first_seen,
       count(*) FILTER (WHERE created_at > now() - interval '60 seconds')::int AS attempts_60,
       count(DISTINCT destination_ip)::int AS hosts,
       max(process) AS process
     FROM events
     WHERE source_ip=$1
       AND destination_port IS NOT NULL
       AND destination_port <> ALL($3::int[])
       AND created_at > now() - interval '120 seconds'`,
    [event.sourceIp, sensitiveScanPorts, noisyScanPorts]
  );
  const row = r.rows[0];
  if(!row) return null;
  const score = scorePortScan({...row, source_ip:event.sourceIp, process:row.process || event.process});
  if(!score.shouldAlert) return null;
  const evidence = {
    source_ip: event.sourceIp,
    hostname: event.hostname,
    process: row.process || event.process || '',
    attempts: row.attempts,
    attempts_60: row.attempts_60,
    unique_ports: row.ports,
    unique_hosts: row.hosts,
    port_list: row.port_list || [],
    sensitive_ports: row.sensitive_ports || [],
    score: score.score,
    severity: score.severity,
    reasons: score.reasons,
    window: '120 seconds',
    first_seen: row.first_seen,
    last_seen: row.last_seen
  };
  const alert = await pool.query(
    `INSERT INTO alerts(title,severity,status,hostname,source_ip,process,matched_term,mitre,recommendation,evidence)
     VALUES('Posible escaneo de puertos',$1,'new',$2,$3,$4,$5,'T1046','Correlacion real de port scanning. Validar puertos unicos, hosts destino y proceso antes de bloquear.',$6)
     RETURNING *`,
    [score.severity, event.hostname, event.sourceIp, evidence.process, 'score ' + score.score + ': ' + score.reasons.join('; '), JSON.stringify(evidence)]
  );
  return alert.rows[0];
}

async function ingestRawEvents(payload){
  const items = Array.isArray(payload) ? payload : [payload];
  const created=[];
  for(const raw of items){
    const e = normalize(raw);
    e.sourceIp = normalizeIpValue(e.sourceIp);
    e.destinationIp = normalizeIpValue(e.destinationIp);
    if(isOwnDeviceIp(e.sourceIp) && (!e.destinationIp || isOwnDeviceIp(e.destinationIp))) continue;
    const ev = await pool.query(
      `INSERT INTO events(event_id,provider,hostname,username,process,command_line,source_ip,source_port,destination_ip,destination_port,protocol,file_path,raw)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [e.eventId,e.provider,e.hostname,e.username,e.process,e.commandLine,e.sourceIp,e.sourcePort,e.destinationIp,e.destinationPort,e.protocol,e.filePath,e.raw]
    );
    io.emit('event:new', ev.rows[0]);
    const scanAlert = await detectImmediatePortScan(e).catch(()=>null);
    if(scanAlert){
      io.emit('alert:new', scanAlert);
      created.push(scanAlert);
    }
    const alerts = analyzeEvent(e);
    for(const a of alerts){
      if(isOwnDeviceIp(a.sourceIp)) continue;
      if(await hasRecentDuplicateAlert(a)) continue;
      const al = await pool.query(`INSERT INTO alerts(event_ref,title,severity,hostname,username,process,source_ip,file_path,matched_term,mitre,recommendation,evidence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,[ev.rows[0].id,a.title,a.severity,a.hostname,a.username,a.process,a.sourceIp,a.filePath,a.matchedTerm,a.mitre,a.recommendation,a.evidence]);
      io.emit('alert:new', al.rows[0]);
      created.push(al.rows[0]);
    }
  }
  scheduleCorrelation();
  return created;
}

function scheduleCorrelation(){
  if(correlationTimer) return;
  correlationTimer = setTimeout(async ()=>{
    correlationTimer = null;
    if(correlationRunning) return scheduleCorrelation();
    correlationRunning = true;
    try {
      await runCorrelation(io, {localIps: trustedLocalIps()});
    } catch {
      // Correlation is secondary; ingestion must stay realtime.
    } finally {
      correlationRunning = false;
    }
  }, 1200);
}

async function cleanupLocalNoiseAlerts(){
  const localAddresses = trustedLocalIps();
  if(!localAddresses.length) return 0;
  const result = await pool.query(
    `DELETE FROM alerts
     WHERE title='Posible escaneo de puertos'
       AND source_ip IS NOT NULL
       AND (
         regexp_replace(lower(source_ip), '%.*$', '') = ANY($1::text[])
         OR lower(source_ip) LIKE 'fe80:%'
         OR lower(source_ip) LIKE 'fd%'
         OR source_ip LIKE '10.%'
         OR source_ip LIKE '192.168.%'
         OR source_ip ~ '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'
         OR source_ip IN ('127.0.0.1','::1','192.168.42.1','fd0d:edc3:e12a::1')
         OR (
           severity IN ('critical','high')
           AND coalesce((evidence->>'score')::int, 0) < 75
         )
         OR (
           severity IN ('critical','high')
           AND coalesce((evidence->>'unique_ports')::int, (evidence->>'ports')::int, 0) <= 15
           AND coalesce((evidence->>'unique_hosts')::int, 0) <= 3
         )
       )
     RETURNING id`,
    [localAddresses]
  );
  for(const row of result.rows) io.emit('alert:delete',{id:row.id});
  return result.rowCount;
}
app.post('/api/events', async (req,res)=>{
  const created = await ingestRawEvents(req.body);
  res.json({ok:true, alerts:created.length});
});
app.get('/api/events', async (_,res)=>{ const r=await pool.query('SELECT * FROM events ORDER BY created_at DESC LIMIT 200'); res.json(r.rows); });
app.get('/api/alerts', async (_,res)=>{ const r=await pool.query('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200'); res.json(r.rows); });
app.get('/api/actions', async (_,res)=>{ const r=await pool.query('SELECT * FROM actions ORDER BY created_at DESC LIMIT 100'); res.json(r.rows); });
app.get('/api/blocked-ips', async (_,res)=>{
  const r=await pool.query("SELECT * FROM blocked_ips WHERE status='blocked' ORDER BY updated_at DESC");
  res.json(r.rows);
});
app.get('/api/network', async (_,res)=>{
  const localAddresses = trustedLocalIps();
  const blocked = await pool.query("SELECT ip FROM blocked_ips WHERE status='blocked'");
  const blockedIpList = blocked.rows.map((row)=>row.ip);
  const [events, sources, ports] = await Promise.all([
    pool.query(`SELECT * FROM events WHERE source_ip IS NOT NULL AND source_ip <> '' ORDER BY created_at DESC LIMIT 200`),
    pool.query(`SELECT
                  source_ip,
                  count(*)::int AS attempts,
                  count(DISTINCT destination_port)::int AS ports,
                  array_agg(DISTINCT destination_port ORDER BY destination_port) FILTER (WHERE destination_port = ANY($3::int[])) AS sensitive_ports,
                  max(created_at) AS last_seen,
                  count(DISTINCT destination_ip)::int AS hosts,
                  ((count(*) > 10 AND count(DISTINCT destination_port) > 15)
                    OR count(DISTINCT destination_port) > 25
                    OR count(DISTINCT destination_ip) > 3) AS is_attack
                FROM events
                WHERE source_ip IS NOT NULL
                  AND source_ip <> ''
                  AND NOT (regexp_replace(lower(source_ip), '%.*$', '') = ANY($1::text[]))
                  AND NOT (source_ip = ANY($2::text[]))
                  AND destination_port IS NOT NULL
                  AND destination_port NOT IN (137,138,1900,5353)
                  AND (destination_ip IS NULL OR (
                    destination_ip NOT LIKE '224.%'
                    AND destination_ip NOT LIKE '239.%'
                    AND destination_ip NOT LIKE 'ff%'
                    AND destination_ip <> '255.255.255.255'
                  ))
                  AND created_at > now() - interval '24 hours'
                GROUP BY source_ip
                ORDER BY attempts DESC
                LIMIT 30`, [localAddresses, blockedIpList, sensitiveScanPorts]),
    pool.query(`SELECT destination_port, count(*)::int AS hits
                FROM events
                WHERE destination_port IS NOT NULL
                  AND destination_port NOT IN (137,138,1900,5353)
                  AND created_at > now() - interval '24 hours'
                GROUP BY destination_port
                ORDER BY hits DESC
                LIMIT 30`)
  ]);
  res.json({events:events.rows, sources:sources.rows, ports:ports.rows});
});
app.get('/api/attacks', async (_,res)=>{
  const localAddresses = trustedLocalIps();
  const r = await pool.query(
    `SELECT
       source_ip,
       max(hostname) AS hostname,
       count(*)::int AS attempts,
       count(DISTINCT destination_port)::int AS ports,
       array_agg(DISTINCT destination_port ORDER BY destination_port) FILTER (WHERE destination_port IS NOT NULL) AS port_list,
       array_agg(DISTINCT destination_port ORDER BY destination_port) FILTER (WHERE destination_port = ANY($2::int[])) AS sensitive_ports,
       max(created_at) AS last_seen,
       min(created_at) AS first_seen
     FROM events
     WHERE source_ip IS NOT NULL
       AND source_ip <> ''
       AND NOT (regexp_replace(lower(source_ip), '%.*$', '') = ANY($1::text[]))
       AND created_at > now() - interval '24 hours'
     GROUP BY source_ip
     ORDER BY last_seen DESC
     LIMIT 80`,
    [localAddresses, sensitiveScanPorts]
  );
  const items = [];
  for(const row of r.rows){
    const intel = await getIpIntel(row.source_ip);
    const alertSeverity = await pool.query(
      `SELECT severity, created_at FROM alerts WHERE source_ip=$1 AND created_at > now() - interval '24 hours'
       ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, created_at DESC LIMIT 1`,
      [row.source_ip]
    );
    const scanScore = scorePortScan(row);
    const severity = alertSeverity.rows[0]?.severity || scanScore.severity;
    const lastSeenMs = new Date(row.last_seen).getTime();
    const alertMs = alertSeverity.rows[0]?.created_at ? new Date(alertSeverity.rows[0].created_at).getTime() : 0;
    const recentWindowMs = 10 * 60 * 1000;
    const isAttack = scanScore.shouldAlert && ['critical','high'].includes(severity) && (Date.now() - Math.max(lastSeenMs, alertMs) <= recentWindowMs);
    items.push({...row, intel, severity, score:scanScore.score, reasons:scanScore.reasons, is_attack:isAttack});
  }
  res.json(items);
});
app.get('/api/ip/:ip/intel', async (req,res)=>{
  const intel = await getIpIntel(req.params.ip);
  res.json(intel || {error:'ip requerida'});
});
app.get('/api/timeline', async (req,res)=>{
  const timeline = await buildTimeline({ip:String(req.query.ip || ''), alertId:String(req.query.alertId || ''), minutes:Number(req.query.minutes || 120)});
  res.json(timeline);
});
app.get('/api/mitre/coverage', async (_,res)=>{
  const r = await pool.query(
    `SELECT coalesce(mitre,'Sin MITRE') AS technique, count(*)::int AS alerts,
            max(created_at) AS last_seen,
            max(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS max_rank
     FROM alerts
     GROUP BY coalesce(mitre,'Sin MITRE')
     ORDER BY max_rank DESC, alerts DESC`
  );
  res.json(r.rows);
});
app.get('/api/reports', async (_,res)=>{
  const reportsDir = path.join(projectRoot, 'reports');
  if(!fs.existsSync(reportsDir)) return res.json([]);
  const files = fs.readdirSync(reportsDir)
    .filter((name)=>/\.(md|html)$/i.test(name))
    .map((name)=>{
      const full = path.join(reportsDir, name);
      const stat = fs.statSync(full);
      return {name, path:full, size:stat.size, updated_at:stat.mtime};
    })
    .sort((a,b)=>new Date(b.updated_at)-new Date(a.updated_at));
  res.json(files);
});
app.get('/api/quarantine', async (_,res)=>{
  const quarantineDir = path.join(process.env.ProgramData || 'C:\\ProgramData', 'SOCSentinel', 'Quarantine');
  if(!fs.existsSync(quarantineDir)) return res.json({path:quarantineDir, items:[]});
  const items = fs.readdirSync(quarantineDir)
    .map((name)=>{
      const full = path.join(quarantineDir, name);
      const stat = fs.statSync(full);
      return {name, path:full, size:stat.size, created_at:stat.birthtime, updated_at:stat.mtime};
    })
    .sort((a,b)=>new Date(b.updated_at)-new Date(a.updated_at));
  res.json({path:quarantineDir, items});
});
app.get('/api/pro/status', async (_,res)=>{
  const [mitre, reports, actions] = await Promise.all([
    pool.query("SELECT count(DISTINCT mitre)::int AS total FROM alerts WHERE mitre IS NOT NULL AND mitre <> ''"),
    Promise.resolve(fs.existsSync(path.join(projectRoot, 'reports')) ? fs.readdirSync(path.join(projectRoot, 'reports')).filter((name)=>/\.(md|html)$/i.test(name)).length : 0),
    pool.query('SELECT count(*)::int AS total FROM actions')
  ]);
  res.json({
    ok:true,
    auth:{mode:'local-env', enabled:Boolean(process.env.SOC_USERNAME || process.env.SOC_PASSWORD), user:process.env.SOC_USERNAME || 'analyst'},
    windowsService:{installer:'scripts/install_windows_service.ps1', uninstall:'scripts/uninstall_windows_service.ps1'},
    quarantine:{mode:'local', path:path.join(process.env.ProgramData || 'C:\\ProgramData', 'SOCSentinel', 'Quarantine')},
    reports:{mode:'markdown-html', count:reports},
    mitre:{techniques:mitre.rows[0].total},
    evtx:{importer:'scripts/import_evtx.ps1'},
    sigmaYara:{mode:'local-rule-pack', paths:['rules/sigma-basic.json','rules/yara-basic.yar']},
    actions:actions.rows[0].total
  });
});
app.post('/api/auth/login', async (req,res)=>{
  const username = String(req.body?.username || '');
  const password = String(req.body?.password || '');
  const expectedUser = process.env.SOC_USERNAME || 'analyst';
  const expectedPass = process.env.SOC_PASSWORD || process.env.RESPONSE_SHARED_SECRET || 'change-this-secret';
  if(username === expectedUser && password === expectedPass){
    return res.json({ok:true, user:{username:expectedUser, role:'SOC Analyst'}});
  }
  res.status(401).json({ok:false, error:'credenciales invalidas'});
});
app.get('/api/email/threats', async (_,res)=>{
  const r=await pool.query('SELECT * FROM email_threats ORDER BY created_at DESC LIMIT 100');
  res.json(r.rows);
});
app.post('/api/email/analyze', async (req,res)=>{
  const rawEmail = String(req.body?.rawEmail || '');
  if(!rawEmail.trim()) return res.status(400).json({error:'rawEmail requerido'});
  const analysis = analyzeEmailThreat(rawEmail);
  const ev = await pool.query(
    `INSERT INTO events(event_id,provider,hostname,username,process,command_line,source_ip,raw)
     VALUES(9100,'Email Threat Monitor',$1,$2,$3,$4,$5,$6) RETURNING *`,
    [process.env.COMPUTERNAME || 'unknown', analysis.sender || 'unknown', 'email', analysis.subject, analysis.sender || '', {analysis, rawEmail}]
  );
  const stored = await pool.query(
    `INSERT INTO email_threats(event_ref,sender,recipient,subject,severity,score,indicators,urls,attachments,raw)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
    [ev.rows[0].id, analysis.sender, analysis.recipient, analysis.subject, analysis.severity, analysis.score, JSON.stringify(analysis.indicators), JSON.stringify(analysis.urls), JSON.stringify(analysis.attachments), JSON.stringify({analysis, rawEmail})]
  );
  if(['critical','high'].includes(analysis.severity)){
    const alert = await pool.query(
      `INSERT INTO alerts(event_ref,title,severity,status,hostname,username,process,source_ip,email_sender,email_recipient,email_subject,email_score,matched_term,mitre,recommendation,evidence)
       VALUES($1,'Posible phishing por correo',$2,'new',$3,'email-monitor','email',NULL,$4,$5,$6,$7,$8,'T1566','No abrir enlaces ni adjuntos. Bloquear remitente/dominio, revisar URLs y analizar adjuntos en sandbox.',$9)
       RETURNING *`,
      [ev.rows[0].id, analysis.severity, process.env.COMPUTERNAME || 'unknown', analysis.sender || '', analysis.recipient || '', analysis.subject || '', analysis.score, `score ${analysis.score}: ${analysis.indicators.slice(0,3).join(', ')}`, JSON.stringify(analysis)]
    );
    io.emit('alert:new', alert.rows[0]);
  }
  io.emit('event:new', ev.rows[0]);
  res.json({ok:true, analysis:stored.rows[0]});
});
app.get('/api/stats', async (_,res)=>{
  const [events, alerts, critical, actions, hosts] = await Promise.all([
    pool.query('SELECT count(*)::int AS total FROM events'),
    pool.query('SELECT count(*)::int AS total FROM alerts'),
    pool.query("SELECT count(*)::int AS total FROM alerts WHERE severity IN ('critical','high')"),
    pool.query('SELECT count(*)::int AS total FROM actions'),
    pool.query("SELECT count(DISTINCT hostname)::int AS total FROM events WHERE hostname IS NOT NULL AND hostname <> ''")
  ]);
  res.json({events:events.rows[0].total, alerts:alerts.rows[0].total, critical:critical.rows[0].total, actions:actions.rows[0].total, hosts:hosts.rows[0].total});
});
app.get('/api/hunt', async (req,res)=>{
  const q = String(req.query.q || '').trim();
  const values = [];
  let where = '';
  if(q){
    values.push(`%${q.toLowerCase()}%`);
    where = `WHERE lower(coalesce(hostname,'') || ' ' || coalesce(username,'') || ' ' || coalesce(process,'') || ' ' || coalesce(command_line,'') || ' ' || coalesce(source_ip,'') || ' ' || raw::text) LIKE $1`;
  }
  const r=await pool.query(`SELECT * FROM events ${where} ORDER BY created_at DESC LIMIT 200`, values);
  res.json(r.rows);
});
app.patch('/api/alerts/:id', async (req,res)=>{
  const allowedClassifications = ['unclassified','true_positive','false_positive','benign_true_positive','needs_review'];
  const current = await pool.query('SELECT * FROM alerts WHERE id=$1', [req.params.id]);
  if(!current.rowCount) return res.status(404).json({error:'alerta no encontrada'});
  const nextStatus = req.body.status ?? current.rows[0].status ?? 'new';
  const nextClassification = req.body.classification ?? current.rows[0].classification ?? 'unclassified';
  if(!allowedClassifications.includes(nextClassification)) return res.status(400).json({error:'clasificacion invalida'});
  const nextNotes = req.body.analyst_notes ?? current.rows[0].analyst_notes ?? null;
  const classifiedAt = req.body.classification ? new Date() : current.rows[0].classified_at;
  const r=await pool.query(
    'UPDATE alerts SET status=$1, classification=$2, analyst_notes=$3, classified_at=$4 WHERE id=$5 RETURNING *',
    [nextStatus,nextClassification,nextNotes,classifiedAt,req.params.id]
  );
  io.emit('alert:update', r.rows[0]);
  res.json(r.rows[0]);
});
app.delete('/api/alerts/:id', async (req,res)=>{ await pool.query('DELETE FROM alerts WHERE id=$1',[req.params.id]); io.emit('alert:delete',{id:req.params.id}); res.json({ok:true, note:'Eliminada del SIEM, no del equipo.'}); });
app.delete('/api/maintenance/noisy-alerts', async (_,res)=>{
  const deleted = await pool.query(`DELETE FROM alerts WHERE title='Login exitoso' OR (event_ref IN (SELECT id FROM events WHERE event_id=4624) AND severity='info') RETURNING id`);
  for(const row of deleted.rows) io.emit('alert:delete',{id:row.id});
  res.json({ok:true, deleted:deleted.rowCount});
});
app.delete('/api/maintenance/purge', async (req,res)=>{
  const secret = req.body?.secret || req.query?.secret;
  if(secret !== process.env.RESPONSE_SHARED_SECRET) return res.status(403).json({error:'secret invalido'});
  await pool.query('DELETE FROM actions');
  await pool.query('DELETE FROM incident_alerts');
  await pool.query('DELETE FROM incidents');
  await pool.query('DELETE FROM alerts');
  await pool.query('DELETE FROM events');
  io.emit('maintenance:purge',{ok:true});
  res.json({ok:true});
});

async function pollFirewallLog(){
  const logPath = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'LogFiles', 'Firewall', 'pfirewall.log');
  try {
    if(!fs.existsSync(logPath)) return;
    const lines = fs.readFileSync(logPath, 'utf8').split(/\r?\n/).filter(Boolean).slice(-400);
    const fresh = [];
    for(const line of lines){
      const key = line.trim();
      if(!key || key.startsWith('#') || seenFirewallLines.has(key)) continue;
      seenFirewallLines.add(key);
      const event = parseFirewallLine(key);
      if(event) fresh.push(event);
    }
    while(seenFirewallLines.size > 2000){
      const first = seenFirewallLines.values().next().value;
      seenFirewallLines.delete(first);
    }
    if(fresh.length) await ingestRawEvents(fresh);
    lastFirewallError = '';
  } catch (error) {
    lastFirewallError = error.message;
  }
}

function seedFirewallBaseline(){
  const logPath = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'LogFiles', 'Firewall', 'pfirewall.log');
  try {
    if(!fs.existsSync(logPath)) return;
    const lines = fs.readFileSync(logPath, 'utf8').split(/\r?\n/).filter(Boolean).slice(-500);
    for(const line of lines){
      const key = line.trim();
      if(key && !key.startsWith('#')) seenFirewallLines.add(key);
    }
    lastFirewallError = '';
  } catch (error) {
    lastFirewallError = error.message;
  }
}

app.get('/api/firewall/status', async (_,res)=>{
  const logPath = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'LogFiles', 'Firewall', 'pfirewall.log');
  let stat = null;
  try {
    if(fs.existsSync(logPath)){
      const info = fs.statSync(logPath);
      stat = {path:logPath, size:info.size, updated:info.mtime};
    }
  } catch (error) {
    lastFirewallError = error.message;
  }
  res.json({ok:!lastFirewallError, lastFirewallError, stat, seen:seenFirewallLines.size});
});

function runPowerShellJson(scriptName, args = []){
  return new Promise((resolve)=>{
    const scriptPath = path.join(projectRoot, 'scripts', scriptName);
    if(!fs.existsSync(scriptPath)) return resolve({ok:false, error:`Script no encontrado: ${scriptPath}`});
    execFile('powershell.exe', ['-NoProfile','-ExecutionPolicy','Bypass','-File',scriptPath, ...args], {timeout:45000}, (err, stdout, stderr)=>{
      if(err) return resolve({ok:false, error:(stderr || err.message || '').trim()});
      try {
        resolve(JSON.parse(stdout));
      } catch (error) {
        resolve({ok:false, error:`Salida no JSON: ${error.message}`, raw:stdout, stderr});
      }
    });
  });
}

async function raiseDefenderAlerts(status){
  const detections = Array.isArray(status?.detections) ? status.detections : [];
  const active = detections.filter((item)=>item.actionSuccess === false);
  for(const item of active.slice(0, 10)){
    if(isBenignDefenderExplorerDetection(item)) continue;
    const resource = Array.isArray(item.resources) ? item.resources[0] : '';
    const alert = {
      title: 'Microsoft Defender detecto amenaza',
      severity: 'critical',
      hostname: process.env.COMPUTERNAME || 'unknown',
      username: item.domainUser || 'SYSTEM',
      process: item.processName || 'Microsoft Defender',
      sourceIp: '',
      filePath: resource || '',
      matchedTerm: item.threatName || `ThreatID ${item.threatId}`,
      mitre: 'T1204',
      recommendation: 'Revisar evidencia de Defender. Ejecutar escaneo, aislar si hay ejecucion activa y remediar solo cuando el origen este confirmado.',
      evidence: item
    };
    if(await hasRecentDuplicateAlert(alert)) continue;
    const ev = await pool.query(
      `INSERT INTO events(event_id,provider,hostname,username,process,file_path,raw)
       VALUES(1116,'Microsoft Defender',$1,$2,$3,$4,$5) RETURNING *`,
      [alert.hostname, alert.username, alert.process, alert.filePath, JSON.stringify({defenderDetection:item})]
    );
    const al = await pool.query(
      `INSERT INTO alerts(event_ref,title,severity,hostname,username,process,source_ip,file_path,matched_term,mitre,recommendation,evidence)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [ev.rows[0].id, alert.title, alert.severity, alert.hostname, alert.username, alert.process, alert.sourceIp, alert.filePath, alert.matchedTerm, alert.mitre, alert.recommendation, JSON.stringify(alert.evidence)]
    );
    io.emit('event:new', ev.rows[0]);
    io.emit('alert:new', al.rows[0]);
  }
}

function isBenignDefenderExplorerDetection(item){
  const processName = String(item?.processName || '').replace(/\//g,'\\').toLowerCase();
  if(!['c:\\windows\\explorer.exe','explorer.exe'].includes(processName)) return false;
  const resources = Array.isArray(item?.resources) ? item.resources.map((value)=>String(value || '').replace(/\//g,'\\').toLowerCase()).filter(Boolean) : [];
  const hasRiskyResource = resources.some((resource)=>(
    resource.includes('\\appdata\\local\\temp\\') ||
    resource.includes('\\windows\\temp\\') ||
    resource.includes('\\users\\public\\') ||
    resource.includes('\\programdata\\') ||
    /\.(exe|dll|ps1|vbs|js|bat|cmd|scr|lnk)$/i.test(resource)
  ));
  const threatName = String(item?.threatName || '').trim();
  return !hasRiskyResource && (!threatName || /^unknown$/i.test(threatName));
}

app.get('/api/defender/status', async (_,res)=>{
  const rawStatus = await runPowerShellJson('defender_status.ps1');
  if(rawStatus.ok) await raiseDefenderAlerts(rawStatus).catch(()=>{});
  res.json(filterDismissedDefenderDetections(rawStatus));
});

app.post('/api/defender/clear-handled', async (_,res)=>{
  const status = await runPowerShellJson('defender_status.ps1');
  if(!status.ok) return res.status(500).json(status);
  const handled = (Array.isArray(status.detections) ? status.detections : []).filter((item)=>item.actionSuccess === true);
  const dismissed = readJsonFile(defenderDismissedPath, {keys:[]});
  const keys = new Set(Array.isArray(dismissed.keys) ? dismissed.keys : []);
  for(const item of handled) keys.add(defenderDetectionKey(item));
  writeJsonFile(defenderDismissedPath, {keys:[...keys], updatedAt:new Date().toISOString()});
  const filtered = filterDismissedDefenderDetections(status);
  res.json({ok:true, hidden:handled.length, defender:filtered});
});

async function resolveExistingAlertId(alertId){
  if(!alertId) return null;
  const result = await pool.query('SELECT id FROM alerts WHERE id=$1 LIMIT 1', [alertId]);
  return result.rowCount ? alertId : null;
}

async function insertActionRecord({ alertId, type, target, status, output }){
  const existingAlertId = await resolveExistingAlertId(alertId);
  return pool.query(
    'INSERT INTO actions(alert_id,action_type,target,status,output) VALUES($1,$2,$3,$4,$5) RETURNING *',
    [existingAlertId, type, target, status, output]
  );
}

app.post('/api/actions/:type', async (req,res)=>{
  const allowed = process.env.ALLOW_RESPONSE_ACTIONS === 'true';
  let {target, alertId, secret}=req.body;
  if(req.params.type === 'defender_scan' && !target) target = 'QuickScan';
  if(req.params.type === 'enable_firewall_logging' && !target) target = 'local';
  if(req.params.type === 'disable_firewall_logging' && !target) target = 'local';
  if(req.params.type === 'generate_report' && !target) target = alertId || 'manual';
  if(!target) return res.status(400).json({error:'target requerido'});
  if(!allowed || secret !== process.env.RESPONSE_SHARED_SECRET) {
    const r=await insertActionRecord({ alertId, type:req.params.type, target, status:'audit-only', output:'AcciÃ³n registrada en modo auditorÃ­a. No se ejecutÃ³ en el sistema.' });
    return res.json(r.rows[0]);
  }
  if(req.params.type === 'generate_report'){
    try {
      const reportPath = await generateIncidentReport({target, alertId});
      const r=await insertActionRecord({ alertId, type:req.params.type, target, status:'executed', output:`Reporte generado: ${reportPath}` });
      io.emit('action:new', r.rows[0]);
      return res.json(r.rows[0]);
    } catch (error) {
      const r=await insertActionRecord({ alertId, type:req.params.type, target, status:'failed', output:error.message });
      io.emit('action:new', r.rows[0]);
      return res.json(r.rows[0]);
    }
  }
  const scriptMap={ block_ip:'block_ip.ps1', unblock_ip:'unblock_ip.ps1', block_port:'block_port.ps1', isolate_host:'isolate_host.ps1', defender_scan:'defender_scan.ps1', locate_malware:'locate_malware.ps1', remove_malware:'remove_malware.ps1', quarantine_file:'quarantine_file.ps1', kill_process:'kill_process.ps1', enable_firewall_logging:'enable_firewall_logging.ps1', disable_firewall_logging:'disable_firewall_logging.ps1' };
  const script=scriptMap[req.params.type];
  if(!script) return res.status(400).json({error:'acciÃ³n no soportada'});
  const scriptPath=path.join(projectRoot,'scripts',script);
  if(!fs.existsSync(scriptPath)) {
    return res.status(500).json({error:`Script no encontrado: ${scriptPath}`});
  }
  execFile('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-File',scriptPath,target], async (err, stdout, stderr)=>{
    try {
      const status = err ? 'failed':'executed';
      const output = (stdout||'') + (stderr||'') + (err?err.message:'');
      const r=await insertActionRecord({ alertId, type:req.params.type, target, status, output });
      if(req.params.type === 'block_ip' && status === 'executed'){
        await pool.query(
          `INSERT INTO blocked_ips(ip,reason,status,last_action_id,updated_at)
           VALUES($1,$2,'blocked',$3,now())
           ON CONFLICT(ip) DO UPDATE SET status='blocked', reason=EXCLUDED.reason, last_action_id=EXCLUDED.last_action_id, updated_at=now()`,
          [target, alertId ? `alert:${alertId}` : 'manual', r.rows[0].id]
        );
        io.emit('blocked_ip:update',{ip:target,status:'blocked'});
      }
      if(req.params.type === 'unblock_ip' && status === 'executed'){
        await pool.query("UPDATE blocked_ips SET status='unblocked', last_action_id=$2, updated_at=now() WHERE ip=$1",[target, r.rows[0].id]);
        io.emit('blocked_ip:update',{ip:target,status:'unblocked'});
      }
      io.emit('action:new', r.rows[0]);
      if(!res.headersSent) res.json(r.rows[0]);
    } catch (error) {
      console.error('action failed', error);
      if(!res.headersSent) res.status(500).json({ error:error.message });
    }
  });
});
const port=process.env.PORT||4000; server.listen(port,()=>{
  refreshLocalAssets();
  console.log(`SOCSentinel Pro V3 API on ${port}`);
  console.log(`Local assets: ${localAssetCache.hostname} ${localAssetCache.ips.join(', ')}`);
  setInterval(refreshLocalAssets, 60000);
  cleanupLocalNoiseAlerts().then((count)=>{
    if(count) console.log(`Cleaned local false-positive scan alerts: ${count}`);
  }).catch(()=>{});
  seedFirewallBaseline();
  if(process.env.ENABLE_BACKEND_FIREWALL_POLL === 'true'){
    setInterval(()=>pollFirewallLog().catch(()=>{}), 5000);
  }
});

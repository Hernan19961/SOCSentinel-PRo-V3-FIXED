import { pool } from '../db/pool.js';
function normalizeIpValue(ip){
  return String(ip || '')
    .trim()
    .toLowerCase()
    .replace(/^::ffff:/, '')
    .replace(/%.+$/, '');
}

function ownDeviceIps(){
  return ['127.0.0.1', '::1', '192.168.42.1', 'fd0d:edc3:e12a::1'];
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
  return ['chrome.exe','msedge.exe','svchost.exe','system','powershell.exe'].some((name)=>normalized === name || normalized.endsWith('\\' + name));
}

function scorePortScan(row){
  const attempts = Number(row?.attempts || 0);
  const attempts60 = Number(row?.attempts_60 || attempts);
  const uniquePorts = Number(row?.ports || 0);
  const uniqueHosts = Number(row?.hosts || 0);
  const sensitivePorts = Array.isArray(row?.sensitive_ports) ? row.sensitive_ports.map(Number).filter(Boolean) : [];
  const reasons = [];
  let score = 0;
  if(attempts60 > 10){ score += 25; reasons.push(attempts60 + ' intentos en 60s'); }
  if(uniquePorts >= 2 && sensitivePorts.length >= 2){ score += 45; reasons.push('posible escaneo sigiloso: ' + sensitivePorts.length + ' puertos de reconocimiento'); }
  if(uniquePorts > 15){ score += 35; reasons.push(uniquePorts + ' puertos unicos en 120s'); }
  if(uniquePorts > 25){ score += 25; reasons.push('mas de 25 puertos unicos (' + uniquePorts + ')'); }
  if(uniqueHosts > 3){ score += 25; reasons.push(uniqueHosts + ' hosts destino en menos de 2 minutos'); }
  if(sensitivePorts.length){ score += 15; reasons.push('puertos sensibles tocados: ' + sensitivePorts.join(', ')); }
  if(uniquePorts <= 3 && uniqueHosts <= 1 && sensitivePorts.length < 2){ score -= 35; reasons.push('pocos puertos/host: trafico observado, no escaneo'); }
  if(isLocalOrLabIp(row?.source_ip) && uniquePorts < 25 && uniqueHosts <= 3 && sensitivePorts.length < 2){ score -= 45; reasons.push('origen local/lab allowlist'); }
  else if(isLocalOrLabIp(row?.source_ip)){ score -= 10; reasons.push('origen local/lab con patron fuerte de escaneo'); }
  if(isTrustedProcess(row?.process) && uniquePorts <= 15 && uniqueHosts <= 3 && sensitivePorts.length < 2){ score -= 20; reasons.push('proceso confiable: ' + row.process); }
  score = Math.max(0, Math.min(100, score));
  if(process.env.SOC_MODE !== 'production' && score >= 90 && (isLocalOrLabIp(row?.source_ip) || ((uniquePorts < 50 && uniqueHosts < 5) && !sensitivePorts.length))){
    score = 89;
    reasons.push('modo lab/demo: critico reservado para patron claramente malicioso');
  }
  const severity = score >= 90 ? 'critical' : score >= 75 ? 'high' : score >= 60 ? 'medium' : score >= 40 ? 'low' : 'info';
  return {score, severity, shouldAlert:score >= 40, reasons};
}

export async function runCorrelation(io, options = {}){
  const brute = await pool.query(`SELECT hostname, username, count(*)::int AS fails FROM events WHERE event_id=4625 AND created_at > now() - interval '10 minutes' GROUP BY hostname, username HAVING count(*) >= 5`);
  for(const row of brute.rows){
    const activeDuplicate = await pool.query(`SELECT id FROM alerts WHERE title=$1 AND hostname=$2 AND username=$3 AND created_at > now() - interval '10 minutes' LIMIT 1`,['Posible fuerza bruta en curso',row.hostname,row.username]);
    if(!activeDuplicate.rowCount){
      const active=await pool.query(`INSERT INTO alerts(title,severity,status,hostname,username,matched_term,mitre,recommendation,evidence) VALUES($1,'high','new',$2,$3,$4,'T1110','Multiples fallos de autenticacion detectados. Revisar IP origen, usuario objetivo y bloquear si corresponde.',$5) RETURNING *`,['Posible fuerza bruta en curso',row.hostname,row.username,row.fails + ' fallos en 10 minutos',JSON.stringify(row)]);
      io.emit('alert:new', active.rows[0]);
    }
    const success = await pool.query(`SELECT id FROM events WHERE event_id=4624 AND hostname=$1 AND username=$2 AND created_at > now() - interval '10 minutes' LIMIT 1`,[row.hostname,row.username]);
    if(success.rowCount){
      const duplicate = await pool.query(`SELECT id FROM alerts WHERE title=$1 AND hostname=$2 AND username=$3 AND created_at > now() - interval '10 minutes' LIMIT 1`,['Posible fuerza bruta exitosa',row.hostname,row.username]);
      if(duplicate.rowCount) continue;
      const ins=await pool.query(`INSERT INTO alerts(title,severity,status,hostname,username,matched_term,mitre,recommendation,evidence) VALUES($1,'critical','new',$2,$3,$4,'T1110','Posible fuerza bruta exitosa. Revisar usuario, IP origen y sesiones activas.',$5) RETURNING *`,['Posible fuerza bruta exitosa',row.hostname,row.username,row.fails + ' fallos + login exitoso',JSON.stringify(row)]);
      io.emit('alert:new', ins.rows[0]);
    }
  }

  const localAddresses = [...new Set([...(options.localIps || []), ...ownDeviceIps()].map(normalizeIpValue).filter(Boolean))];
  const blocked = await pool.query("SELECT ip FROM blocked_ips WHERE status='blocked'");
  const blockedIps = blocked.rows.map((row)=>row.ip);
  const scans = await pool.query(`
    SELECT
      source_ip,
      max(hostname) AS hostname,
      max(process) AS process,
      count(*)::int AS attempts,
      count(*) FILTER (WHERE created_at > now() - interval '60 seconds')::int AS attempts_60,
      count(DISTINCT destination_port)::int AS ports,
      count(DISTINCT destination_ip)::int AS hosts,
      array_agg(DISTINCT destination_port ORDER BY destination_port) FILTER (WHERE destination_port IS NOT NULL) AS port_list,
      array_agg(DISTINCT destination_port ORDER BY destination_port) FILTER (WHERE destination_port IN (21,22,23,25,53,80,135,139,443,445,3389,5985,8080)) AS sensitive_ports,
      max(created_at) AS last_seen,
      min(created_at) AS first_seen
    FROM events
    WHERE source_ip IS NOT NULL
      AND source_ip <> ''
      AND destination_port IS NOT NULL
      AND destination_port NOT IN (137,138,1900,5353)
      AND NOT (regexp_replace(lower(source_ip), '%.*$', '') = ANY($1::text[]))
      AND NOT (source_ip = ANY($2::text[]))
      AND (destination_ip IS NULL OR (
        destination_ip NOT LIKE '224.%'
        AND destination_ip NOT LIKE '239.%'
        AND destination_ip NOT LIKE 'ff%'
        AND destination_ip <> '255.255.255.255'
      ))
      AND created_at > now() - interval '120 seconds'
    GROUP BY source_ip
  `, [localAddresses, blockedIps]);

  for(const row of scans.rows){
    const score = scorePortScan(row);
    if(!score.shouldAlert) continue;
    const duplicate = await pool.query(
      `SELECT id FROM alerts WHERE title=$1 AND source_ip=$2 AND created_at > now() - interval '5 minutes' LIMIT 1`,
      ['Posible escaneo de puertos', row.source_ip]
    );
    if(duplicate.rowCount) continue;
    const evidence = {
      source_ip: row.source_ip,
      hostname: row.hostname,
      process: row.process || '',
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
       VALUES($1,$2,'new',$3,$4,$5,$6,'T1046','Correlacion real de port scanning. Validar puertos unicos, hosts destino y proceso antes de bloquear.',$7)
       RETURNING *`,
      ['Posible escaneo de puertos', score.severity, row.hostname, row.source_ip, row.process || '', 'score ' + score.score + ': ' + score.reasons.join('; '), JSON.stringify(evidence)]
    );
    io.emit('alert:new', alert.rows[0]);
  }
}

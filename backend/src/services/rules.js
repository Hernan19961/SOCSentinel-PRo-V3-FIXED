export const rules = [
  {name:'PowerShell sospechoso', eventIds:[1,4688], field:'commandLine', terms:['-enc','encodedcommand','downloadstring','invoke-webrequest','iex '], severity:'high', mitre:'T1059.001', recommendation:'Investigar comando, usuario y origen. Escanear archivo/proceso antes de eliminar.'},
  {name:'LOLBin sospechoso', eventIds:[1,4688], field:'rawText', terms:['rundll32.exe','regsvr32.exe','mshta.exe','wscript.exe','cscript.exe','certutil.exe','bitsadmin.exe'], severity:'high', mitre:'T1218', recommendation:'Validar firma, ruta, proceso padre y conexiones de red asociadas.'},
  {name:'Persistencia en registro o tarea', eventIds:[1,4688,4698], field:'rawText', terms:['schtasks','\\run','currentversion\\run','startup','scheduled task'], severity:'high', mitre:'T1053', recommendation:'Revisar autoruns, tareas programadas y cambios recientes de persistencia.'},
  {name:'Ejecucion desde ruta temporal', eventIds:[1,4688,11], field:'rawText', terms:['\\appdata\\local\\temp\\','\\windows\\temp\\','\\users\\public\\','\\programdata\\'], severity:'medium', mitre:'T1204', recommendation:'Ubicar archivo, validar hash/firma y escanear antes de remediar.'},
  {name:'Instalacion de servicio', eventIds:[7045,6], field:'rawText', terms:['service','servicio','installed'], severity:'medium', mitre:'T1543.003', recommendation:'Validar si el servicio fue instalado por software legitimo.'},
  {name:'Usuario creado', eventIds:[4720], field:'rawText', terms:[''], severity:'high', mitre:'T1136', recommendation:'Confirmar autorizacion de creacion de cuenta.'},
  {name:'Password reseteada', eventIds:[4724], field:'rawText', terms:[''], severity:'high', mitre:'T1098', recommendation:'Confirmar ticket/cambio autorizado y revisar actividad posterior del usuario.'},
  {name:'Usuario agregado a grupo privilegiado', eventIds:[4732], field:'rawText', terms:['administrators','administradores','domain admins'], severity:'critical', mitre:'T1098', recommendation:'Validar cambio de privilegios inmediatamente.'},
  {name:'Conexion de red Sysmon', eventIds:[3], field:'rawText', terms:['destinationip','imagen','destinationport'], severity:'info', mitre:'T1041', recommendation:'Validar proceso y destino.'},
  {name:'Creacion de archivo Sysmon', eventIds:[11], field:'rawText', terms:['.exe','.dll','.ps1','.vbs','.js'], severity:'medium', mitre:'T1105', recommendation:'Revisar origen del archivo, hash, firma y usuario que lo creo.'}
];

const benignWindowsProcesses = [
  'c:\\windows\\explorer.exe',
  'c:\\windows\\system32\\explorer.exe'
];

const suspiciousCommandTerms = [
  '-enc',
  'encodedcommand',
  'downloadstring',
  'invoke-webrequest',
  'iex ',
  'rundll32',
  'regsvr32',
  'mshta',
  'certutil',
  'bitsadmin',
  'powershell'
];

export function normalize(raw){
  const rawMessage = raw.rawMessage || raw.Message || '';
  const text = JSON.stringify(raw).toLowerCase();
  const messageText = String(rawMessage).toLowerCase();
  const eventId = Number(raw.eventId ?? raw.Id ?? raw.EventID ?? raw.event_id ?? 0);
  const suppliedProcess = cleanProcess(raw.process || raw.Image || raw.NewProcessName || raw.ProcessName);
  const extractedProcess = extractFromMessage(rawMessage, /Nombre de proceso:\s*([^\r\n]+)/i)
    || extractFromMessage(rawMessage, /New Process Name:\s*([^\r\n]+)/i)
    || extract(text, /(powershell\.exe|cmd\.exe|rundll32\.exe|regsvr32\.exe|mshta\.exe|wscript\.exe|cscript\.exe|certutil\.exe|bitsadmin\.exe|services\.exe)/);
  const extractedUser = extractFromMessage(rawMessage, /Nuevo inicio de sesi[oó]n:[\s\S]*?Nombre de cuenta:\s*([^\r\n]+)/i)
    || extractFromMessage(rawMessage, /New Logon:[\s\S]*?Account Name:\s*([^\r\n]+)/i);
  const extractedIp = extractFromMessage(rawMessage, /Direcci[oó]n de red de origen:\s*([^\r\n]+)/i)
    || extractFromMessage(rawMessage, /Source Network Address:\s*([^\r\n]+)/i);
  const sourceIp = cleanIp(raw.sourceIp || raw.IpAddress || raw.SourceIp || raw.SourceNetworkAddress || raw.source_ip || raw.srcIp || extractedIp || extractFromMessage(rawMessage, /Source Address:\s*([^\r\n]+)/i));
  const destinationIp = cleanIp(raw.destinationIp || raw.DestinationIp || raw.DestinationAddress || raw.destIp || raw.dstIp || extractFromMessage(rawMessage, /Destination Address:\s*([^\r\n]+)/i));
  const sourcePort = cleanPort(raw.sourcePort || raw.SourcePort || raw.srcPort || extractFromMessage(rawMessage, /Source Port:\s*([0-9]+)/i));
  const destinationPort = cleanPort(raw.destinationPort || raw.DestinationPort || raw.destPort || raw.dstPort || extractFromMessage(rawMessage, /Destination Port:\s*([0-9]+)/i));
  const protocol = cleanValue(raw.protocol || raw.Protocol || extractFromMessage(rawMessage, /Protocol:\s*([^\r\n]+)/i)).toUpperCase();
  const processPath = suppliedProcess || cleanValue(extractedProcess);
  const commandLine = raw.commandLine || raw.CommandLine || raw.ProcessCommandLine || rawMessage || '';
  return {
    eventId,
    provider: raw.provider || raw.ProviderName || raw.Provider || 'unknown',
    hostname: raw.hostname || raw.MachineName || raw.Computer || raw.computer || process.env.COMPUTERNAME || 'unknown',
    username: cleanValue(raw.user || raw.username || raw.AccountName || raw.SubjectUserName || raw.User || extractedUser || 'unknown'),
    process: processPath,
    commandLine,
    sourceIp,
    sourcePort,
    destinationIp,
    destinationPort,
    protocol,
    filePath: raw.filePath || raw.TargetFilename || raw.Image || raw.NewProcessName || extract(text, /([a-z]:\\\\[^"']+\.(exe|dll|ps1|vbs|js|bat|cmd))/),
    logonType: extractFromMessage(rawMessage, /Tipo de inicio de sesi[oó]n:\s*([0-9]+)/i) || extractFromMessage(rawMessage, /Logon Type:\s*([0-9]+)/i),
    isBenignServiceLogon: eventId === 4624 && messageText.includes('tipo de inicio de sesi') && messageText.includes('services.exe') && messageText.includes('system'),
    isBenignExplorer: isBenignExplorer(processPath, commandLine, text),
    rawText: text,
    raw
  };
}

function extract(text, re){
  const match = text.match(re);
  return match ? match[1] : '';
}

function extractFromMessage(message, re){
  const match = String(message || '').match(re);
  return match ? cleanValue(match[1]) : '';
}

function cleanValue(value){
  const cleaned = String(value || '').trim();
  return cleaned === '-' ? '' : cleaned;
}

function cleanIp(value){
  const cleaned = cleanValue(value);
  if(!cleaned || cleaned === '::1' || cleaned === '127.0.0.1' || cleaned === '0.0.0.0') return '';
  return cleaned;
}

function cleanPort(value){
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
}

function cleanProcess(value){
  const cleaned = cleanValue(value);
  if(!cleaned) return '';
  if(cleaned.length > 260) return '';
  if(/se inici|firmante:|new logon:|informaci/i.test(cleaned)) return '';
  return cleaned;
}

function normalizePath(value){
  return String(value || '').replace(/\//g,'\\').toLowerCase();
}

function isBenignExplorer(processPath, commandLine, rawText){
  const normalizedProcess = normalizePath(processPath);
  if(!benignWindowsProcesses.includes(normalizedProcess)) return false;
  const lowerCommand = String(commandLine || '').toLowerCase();
  const lowerRaw = String(rawText || '').toLowerCase();
  const hasSuspiciousCommand = suspiciousCommandTerms.some((term)=>lowerCommand.includes(term) || lowerRaw.includes(term));
  const hasTempOrUserDropPath = /\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\programdata\\.*\.(exe|dll|ps1|vbs|js|bat|cmd)/i.test(commandLine) || /\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\programdata\\.*\.(exe|dll|ps1|vbs|js|bat|cmd)/i.test(rawText);
  return !hasSuspiciousCommand && !hasTempOrUserDropPath;
}

export function analyzeEvent(event){
  const alerts=[];
  for(const rule of rules){
    if(!rule.eventIds.includes(event.eventId)) continue;
    if(event.isBenignServiceLogon) continue;
    if(event.isBenignExplorer && ['high','critical'].includes(rule.severity)) continue;
    const value = String(event[rule.field] ?? event.rawText ?? '').toLowerCase();
    const terms = rule.terms.length ? rule.terms : [''];
    for(const term of terms){
      if(term==='' || value.includes(term.toLowerCase())){
        alerts.push({
          title:rule.name,
          severity:rule.severity,
          hostname:event.hostname,
          username:event.username,
          process:event.process,
          sourceIp:event.sourceIp,
          filePath:event.filePath,
          matchedTerm:term || `EventID ${event.eventId}`,
          mitre:rule.mitre,
          recommendation:rule.recommendation,
          evidence:event.raw
        });
        break;
      }
    }
  }
  return alerts;
}

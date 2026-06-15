import dotenv from 'dotenv';
dotenv.config();
import { execFile } from 'child_process';
import fetch from 'node-fetch';
const API=process.env.SOCSENTINEL_API||'http://localhost:4000/api/events';
const POLL=Number(process.env.POLL_SECONDS||5)*1000;
let lastRecordId=0;
const seenFirewallLines = new Set();
function ps(){
return `$logs=@('Security','Microsoft-Windows-Sysmon/Operational');$out=@();foreach($l in $logs){try{$ev=Get-WinEvent -LogName $l -MaxEvents 40 -ErrorAction Stop | Where-Object {$_.Id -in 1,3,6,11,4624,4625,4688,4720,4724,4732,5152,5156,5157,5158,7045} | Select-Object TimeCreated,Id,RecordId,ProviderName,MachineName,Message;$out+=$ev}catch{}};$out|Sort-Object RecordId|ConvertTo-Json -Depth 4`;
}
function firewallPs(){
return `$path="$env:SystemRoot\\System32\\LogFiles\\Firewall\\pfirewall.log";if(Test-Path $path){Get-Content $path -Tail 250 | Where-Object {$_ -and $_ -notlike '#*'} | ConvertTo-Json -Depth 2}`;
}
function parseFirewallLine(line){
 const parts=String(line||'').trim().split(/\s+/);
 if(parts.length<17) return null;
 const [date,time,action,protocol,srcIp,dstIp,srcPort,dstPort,size,tcpFlags,tcpSyn,tcpAck,tcpWin,icmpType,icmpCode,info,path]=parts;
 if(!srcIp||!dstIp||!dstPort) return null;
 return {eventId:9001,provider:'Windows Firewall',hostname:process.env.COMPUTERNAME||'unknown',timestamp:`${date}T${time}`,sourceIp:srcIp,destinationIp:dstIp,sourcePort:Number(srcPort)||null,destinationPort:Number(dstPort)||null,protocol,action,rawMessage:line,raw:{date,time,action,protocol,srcIp,dstIp,srcPort,dstPort,size,tcpFlags,tcpSyn,tcpAck,tcpWin,icmpType,icmpCode,info,path}};
}
function readEvents(){
 execFile('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-Command',ps()],async(err,stdout)=>{
  if(err||!stdout.trim()) return;
  let data=[]; try{data=JSON.parse(stdout); if(!Array.isArray(data)) data=[data];}catch{return;}
  const fresh=data.filter(e=>Number(e.RecordId)>lastRecordId).map(e=>({eventId:e.Id,provider:e.ProviderName,hostname:e.MachineName,recordId:e.RecordId,timestamp:e.TimeCreated,rawMessage:e.Message,raw:e,commandLine:e.Message}));
  if(fresh.length){lastRecordId=Math.max(...fresh.map(e=>Number(e.recordId)||0),lastRecordId); try{await fetch(API,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(fresh)}); console.log('sent',fresh.length,'events');}catch(e){console.error('send failed',e.message)}}
 });
 execFile('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-Command',firewallPs()],async(err,stdout)=>{
  if(err){ console.error('firewall read failed - run agent as Administrator:', err.message); return; }
  if(!stdout.trim()) return;
  let lines=[]; try{lines=JSON.parse(stdout); if(!Array.isArray(lines)) lines=[lines];}catch{return;}
  const freshLines=lines.filter(line=>{
    const key=String(line||'').trim();
    if(!key || seenFirewallLines.has(key)) return false;
    seenFirewallLines.add(key);
    return true;
  });
  while(seenFirewallLines.size>1000){
    const first=seenFirewallLines.values().next().value;
    seenFirewallLines.delete(first);
  }
  const fresh=freshLines.map(parseFirewallLine).filter(Boolean);
  if(fresh.length){try{await fetch(API,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(fresh)}); console.log('sent firewall',fresh.length,'events');}catch(e){console.error('firewall send failed',e.message)}}
 });
}
console.log('SOCSentinel Windows Agent running. API:',API);
setInterval(readEvents,POLL); readEvents();

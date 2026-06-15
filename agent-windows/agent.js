import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
const __dirname=path.dirname(fileURLToPath(import.meta.url));
dotenv.config({path:path.join(__dirname,'.env')});
import { execFile } from 'child_process';
import fetch from 'node-fetch';
const API=process.env.SOCSENTINEL_API||'http://127.0.0.1:4000/api/events';
const HEALTH=API.replace(/\/api\/events\/?$/,'/api/health');
const POLL=Number(process.env.POLL_SECONDS||2)*1000;
const BATCH_SIZE=Number(process.env.BATCH_SIZE||25);
let lastRecordId=0;
let backendOnline=false;
const seenFirewallLines = new Set();
function ps(){
return `$logs=@('Security','Microsoft-Windows-Sysmon/Operational');$out=@();foreach($l in $logs){try{$ev=Get-WinEvent -LogName $l -MaxEvents 80 -ErrorAction Stop | Where-Object {$_.Id -in 1,3,6,11,4624,4625,4688,4720,4724,4732,5152,5156,5157,5158,7045} | Select-Object TimeCreated,Id,RecordId,ProviderName,MachineName,Message;$out+=$ev}catch{}};$out|Sort-Object RecordId|ConvertTo-Json -Depth 4`;
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
function trimEvent(event){
 const rawMessage=String(event.rawMessage||'');
 return {...event,rawMessage:rawMessage.slice(0,6000),commandLine:String(event.commandLine||'').slice(0,6000),raw:event.raw||{}};
}
function chunks(items,size){
 const out=[];
 for(let i=0;i<items.length;i+=size) out.push(items.slice(i,i+size));
 return out;
}
async function checkBackend(){
 try{
  const response=await fetch(HEALTH,{timeout:4000});
  backendOnline=response.ok;
  if(!response.ok) console.error('backend health failed',response.status,response.statusText);
 }catch(e){
  backendOnline=false;
  console.error('backend offline:',e.message || e.type || 'sin detalle');
 }
 return backendOnline;
}
async function sendEvents(events,label='events'){
 if(!events.length) return;
 if(!backendOnline && !(await checkBackend())) return;
 for(const batch of chunks(events.map(trimEvent),BATCH_SIZE)){
  try{
   const response=await fetch(API,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(batch),timeout:12000});
   const text=await response.text();
   if(!response.ok){
    console.error(`${label} send http ${response.status}:`,text.slice(0,500));
    backendOnline=false;
    return;
   }
   console.log('sent',batch.length,label);
  }catch(e){
   backendOnline=false;
   console.error(`${label} send failed:`,e.message || e.type || e.code || 'sin detalle');
   return;
  }
 }
}
function runPowerShell(command,callback){
 try{
  execFile('powershell.exe',['-NoProfile','-ExecutionPolicy','Bypass','-Command',command],callback);
 }catch(e){
  callback(e,'','');
 }
}
function readEvents(){
 runPowerShell(ps(),async(err,stdout)=>{
  if(err){ console.error('event log read failed:',err.message || err.code || 'sin detalle'); return; }
  if(!stdout.trim()) return;
  let data=[]; try{data=JSON.parse(stdout); if(!Array.isArray(data)) data=[data];}catch{return;}
  const fresh=data.filter(e=>Number(e.RecordId)>lastRecordId).map(e=>({eventId:e.Id,provider:e.ProviderName,hostname:e.MachineName,recordId:e.RecordId,timestamp:e.TimeCreated,rawMessage:e.Message,raw:e,commandLine:e.Message}));
  if(fresh.length){lastRecordId=Math.max(...fresh.map(e=>Number(e.recordId)||0),lastRecordId); await sendEvents(fresh,'events');}
 });
 runPowerShell(firewallPs(),async(err,stdout)=>{
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
  if(fresh.length) await sendEvents(fresh,'firewall events');
 });
}
function seedBaselines(){
 return new Promise((resolve)=>{
  let pending=2;
  const done=()=>{ pending-=1; if(pending<=0) resolve(); };
  runPowerShell(ps(),(err,stdout)=>{
   if(!err && stdout.trim()){
    try{
     let data=JSON.parse(stdout); if(!Array.isArray(data)) data=[data];
     lastRecordId=Math.max(...data.map(e=>Number(e.RecordId)||0),lastRecordId);
     console.log('event baseline record',lastRecordId);
    }catch{}
   }
   done();
  });
  runPowerShell(firewallPs(),(err,stdout)=>{
   if(!err && stdout.trim()){
    try{
     let lines=JSON.parse(stdout); if(!Array.isArray(lines)) lines=[lines];
     for(const line of lines){
      const key=String(line||'').trim();
      if(key) seenFirewallLines.add(key);
     }
     console.log('firewall baseline lines',seenFirewallLines.size);
    }catch{}
   }
   done();
  });
 });
}
console.log('SOCSentinel Windows Agent running. API:',API);
checkBackend().then(async()=>{await seedBaselines(); setInterval(readEvents,POLL); readEvents();});

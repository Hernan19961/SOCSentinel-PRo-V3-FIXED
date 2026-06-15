import { pool } from '../db/pool.js';
import os from 'os';

function localIps(){
  return Object.values(os.networkInterfaces())
    .flat()
    .filter(Boolean)
    .map((item)=>item.address)
    .filter(Boolean);
}

export async function runCorrelation(io){
  const brute = await pool.query(`SELECT hostname, username, count(*)::int AS fails FROM events WHERE event_id=4625 AND created_at > now() - interval '10 minutes' GROUP BY hostname, username HAVING count(*) >= 5`);
  for(const row of brute.rows){
    const activeDuplicate = await pool.query(`SELECT id FROM alerts WHERE title=$1 AND hostname=$2 AND username=$3 AND created_at > now() - interval '10 minutes' LIMIT 1`,['Posible fuerza bruta en curso',row.hostname,row.username]);
    if(!activeDuplicate.rowCount){
      const active=await pool.query(`INSERT INTO alerts(title,severity,status,hostname,username,matched_term,mitre,recommendation,evidence) VALUES($1,'high','new',$2,$3,$4,'T1110','Multiples fallos de autenticacion detectados. Revisar IP origen, usuario objetivo y bloquear si corresponde.',$5) RETURNING *`,['Posible fuerza bruta en curso',row.hostname,row.username,`${row.fails} fallos en 10 minutos`,JSON.stringify(row)]);
      io.emit('alert:new', active.rows[0]);
    }
    const success = await pool.query(`SELECT id FROM events WHERE event_id=4624 AND hostname=$1 AND username=$2 AND created_at > now() - interval '10 minutes' LIMIT 1`,[row.hostname,row.username]);
    if(success.rowCount){
      const duplicate = await pool.query(`SELECT id FROM alerts WHERE title=$1 AND hostname=$2 AND username=$3 AND created_at > now() - interval '10 minutes' LIMIT 1`,['Posible fuerza bruta exitosa',row.hostname,row.username]);
      if(duplicate.rowCount) continue;
      const ins=await pool.query(`INSERT INTO alerts(title,severity,status,hostname,username,matched_term,mitre,recommendation,evidence) VALUES($1,'critical','new',$2,$3,$4,'T1110','Posible fuerza bruta exitosa. Revisar usuario, IP origen y sesiones activas.',$5) RETURNING *`,['Posible fuerza bruta exitosa',row.hostname,row.username,`${row.fails} fallos + login exitoso`,JSON.stringify(row)]);
      io.emit('alert:new', ins.rows[0]);
    }
  }

  const localAddresses = localIps();
  const blocked = await pool.query("SELECT ip FROM blocked_ips WHERE status='blocked'");
  const blockedIps = blocked.rows.map((row)=>row.ip);
  const scans = await pool.query(`
    SELECT
      source_ip,
      hostname,
      count(*)::int AS attempts,
      count(DISTINCT destination_port)::int AS ports,
      array_agg(DISTINCT destination_port ORDER BY destination_port) FILTER (WHERE destination_port IS NOT NULL) AS port_list,
      bool_or(destination_port IN (22,23,80,135,139,445,3389,5985,5986)) AS touched_sensitive_port,
      max(created_at) AS last_seen
    FROM events
    WHERE source_ip IS NOT NULL
      AND source_ip <> ''
      AND destination_port IS NOT NULL
      AND destination_port NOT IN (137,138,1900,5353)
      AND NOT (source_ip = ANY($1::text[]))
      AND NOT (source_ip = ANY($2::text[]))
      AND (destination_ip IS NULL OR (
        destination_ip NOT LIKE '224.%'
        AND destination_ip NOT LIKE '239.%'
        AND destination_ip NOT LIKE 'ff%'
        AND destination_ip <> '255.255.255.255'
      ))
      AND created_at > now() - interval '5 minutes'
    GROUP BY source_ip, hostname
    HAVING (count(*) >= 8 AND count(DISTINCT destination_port) >= 3)
        OR (count(*) >= 25 AND count(DISTINCT destination_port) >= 2)
        OR (count(*) >= 6 AND bool_or(destination_port IN (22,23,80,135,139,445,3389,5985,5986)))
        OR count(DISTINCT destination_port) >= 5
  `, [localAddresses, blockedIps]);

  for(const row of scans.rows){
    const duplicate = await pool.query(
      `SELECT id FROM alerts WHERE title=$1 AND source_ip=$2 AND created_at > now() - interval '30 minutes' LIMIT 1`,
      ['Posible escaneo de puertos', row.source_ip]
    );
    if(duplicate.rowCount) continue;
    const evidence = {
      source_ip: row.source_ip,
      hostname: row.hostname,
      attempts: row.attempts,
      ports: row.ports,
      port_list: row.port_list,
      touched_sensitive_port: row.touched_sensitive_port,
      window: '5 minutes',
      last_seen: row.last_seen
    };
    const alert = await pool.query(
      `INSERT INTO alerts(title,severity,status,hostname,source_ip,matched_term,mitre,recommendation,evidence)
       VALUES($1,'high','new',$2,$3,$4,'T1046','Posible reconocimiento de red. Revisar puertos tocados y bloquear IP si no es un escaner autorizado.',$5)
       RETURNING *`,
      ['Posible escaneo de puertos', row.hostname, row.source_ip, `${row.attempts} conexiones / ${row.ports} puertos`, JSON.stringify(evidence)]
    );
    io.emit('alert:new', alert.rows[0]);
  }
}

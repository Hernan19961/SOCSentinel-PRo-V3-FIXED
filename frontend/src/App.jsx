import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { io } from 'socket.io-client';
import {
  Activity,
  AlertTriangle,
  Ban,
  Crosshair,
  Database,
  Eye,
  FileSearch,
  Filter,
  FileText,
  LockOpen,
  Mail,
  MapPin,
  Network,
  Radar,
  RefreshCw,
  ScanLine,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Skull,
  TerminalSquare,
  Trash2,
  WifiOff,
} from 'lucide-react';
import './style.css';

const API = 'http://localhost:4000';

const modules = [
  { id: 'command', label: 'Comando', icon: TerminalSquare },
  { id: 'alerts', label: 'Alertas', icon: ShieldAlert },
  { id: 'events', label: 'Visor', icon: Database },
  { id: 'map', label: 'Mapa', icon: Radar },
  { id: 'network', label: 'Network', icon: Network },
  { id: 'email', label: 'Email', icon: Mail },
  { id: 'defender', label: 'Defender', icon: ShieldCheck },
  { id: 'hunt', label: 'Hunting', icon: Crosshair },
  { id: 'malware', label: 'Malware', icon: Skull },
  { id: 'response', label: 'Respuesta', icon: Ban },
];

const severityRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const classificationLabels = {
  unclassified: 'Sin clasificar',
  needs_review: 'En revision',
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign_true_positive: 'Benigno real',
};

function clsSeverity(severity) {
  return `severity ${severity || 'info'}`;
}

function formatTime(value) {
  if (!value) return '-';
  return new Date(value).toLocaleString();
}

function shortText(value, max = 96) {
  const text = String(value || '-').replace(/\s+/g, ' ').trim();
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

function prettyJson(value) {
  try {
    return JSON.stringify(value ?? {}, null, 2);
  } catch {
    return String(value || '');
  }
}

function scanTarget(alert) {
  return alert?.file_path || alert?.process || 'QuickScan';
}

function fileTarget(alert) {
  return alert?.file_path || alert?.process || '';
}

function isEmailAlert(alert) {
  return alert?.process === 'email' || Boolean(alert?.email_sender);
}

function alertOrigin(alert) {
  if (isEmailAlert(alert)) return alert.email_sender || alert.evidence?.sender || '-';
  return alert?.source_ip || '-';
}

function alertPort(alert) {
  return alert?.destination_port || alert?.evidence?.destination_port || alert?.evidence?.port_list?.[0] || '';
}

function ActionButton({ icon: Icon, label, onClick, disabled, danger }) {
  return (
    <button className={danger ? 'tool danger' : 'tool'} onClick={onClick} disabled={disabled} title={label}>
      <Icon size={16} />
      <span>{label}</span>
    </button>
  );
}

function Stat({ icon: Icon, label, value, tone }) {
  return (
    <div className={`stat ${tone || ''}`}>
      <Icon size={20} />
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function App() {
  const [active, setActive] = useState('command');
  const [alerts, setAlerts] = useState([]);
  const [events, setEvents] = useState([]);
  const [actions, setActions] = useState([]);
  const [networkData, setNetworkData] = useState({ events: [], sources: [], ports: [] });
  const [emailThreats, setEmailThreats] = useState([]);
  const [emailRaw, setEmailRaw] = useState('');
  const [defender, setDefender] = useState(null);
  const [attacks, setAttacks] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [selectedIntel, setSelectedIntel] = useState(null);
  const [blockedIps, setBlockedIps] = useState([]);
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState(null);
  const [secret, setSecret] = useState('change-this-secret');
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [details, setDetails] = useState(null);
  const [alarmAckAt, setAlarmAckAt] = useState(0);
  const [session, setSession] = useState(() => JSON.parse(localStorage.getItem('socsentinel-session') || 'null'));
  const [loginForm, setLoginForm] = useState({ username: 'hernan', password: '' });
  const [loginError, setLoginError] = useState('');
  const [consoleLines, setConsoleLines] = useState([
    '[boot] SOCSentinel Pro iniciado',
    '[mode] Respuesta real activa si backend corre como administrador y el secreto coincide',
  ]);

  async function getJson(path, fallback) {
    try {
      const response = await fetch(`${API}${path}`);
      if (!response.ok) throw new Error(response.statusText);
      return await response.json();
    } catch (error) {
      pushConsole(`error al cargar ${path}: ${error.message}`);
      return fallback;
    }
  }

  function pushConsole(line) {
    setConsoleLines((current) => [`[${new Date().toLocaleTimeString()}] ${line}`, ...current].slice(0, 80));
  }

  async function login(event) {
    event.preventDefault();
    setLoginError('');
    try {
      const response = await fetch(`${API}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginForm),
      });
      const result = await response.json();
      if (!response.ok || !result.ok) throw new Error(result.error || 'credenciales invalidas');
      localStorage.setItem('socsentinel-session', JSON.stringify(result.user));
      setSession(result.user);
      pushConsole(`login: ${result.user.username}`);
      load();
    } catch (error) {
      setLoginError(error.message);
    }
  }

  function logout() {
    localStorage.removeItem('socsentinel-session');
    setSession(null);
  }

  function playSiren() {
    try {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (!AudioContext) return;
      const ctx = new AudioContext();
      const gain = ctx.createGain();
      gain.gain.value = 0.035;
      gain.connect(ctx.destination);
      const now = ctx.currentTime;
      [0, 0.28, 0.56].forEach((offset) => {
        const osc = ctx.createOscillator();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(680, now + offset);
        osc.frequency.linearRampToValueAtTime(1080, now + offset + 0.16);
        osc.frequency.linearRampToValueAtTime(620, now + offset + 0.28);
        osc.connect(gain);
        osc.start(now + offset);
        osc.stop(now + offset + 0.28);
      });
      setTimeout(() => ctx.close(), 1100);
      navigator.vibrate?.([120, 70, 120]);
    } catch {
      // Audio can be blocked by the browser until the user interacts.
    }
  }

  async function load() {
    const [nextAlerts, nextEvents, nextActions, nextStats, nextHealth, nextNetwork, nextBlockedIps, nextEmailThreats, nextDefender, nextAttacks] = await Promise.all([
      getJson('/api/alerts', []),
      getJson('/api/events', []),
      getJson('/api/actions', []),
      getJson('/api/stats', null),
      getJson('/api/health', null),
      getJson('/api/network', { events: [], sources: [], ports: [] }),
      getJson('/api/blocked-ips', []),
      getJson('/api/email/threats', []),
      getJson('/api/defender/status', null),
      getJson('/api/attacks', []),
    ]);
    setAlerts(nextAlerts);
    setEvents(nextEvents);
    setActions(nextActions);
    setStats(nextStats);
    setHealth(nextHealth);
    setNetworkData(nextNetwork);
    setBlockedIps(nextBlockedIps);
    setEmailThreats(nextEmailThreats);
    setDefender(nextDefender);
    setAttacks(nextAttacks);
  }

  useEffect(() => {
    load();
    const socket = io(API);
    socket.on('alert:new', (alert) => {
      setAlerts((current) => [alert, ...current]);
      pushConsole(`alerta ${alert.severity}: ${alert.title}`);
      loadAttackFeed();
      if (['critical', 'high'].includes(alert.severity)) {
        playSiren();
        document.title = `ALERTA ${alert.severity.toUpperCase()} - SOCSentinel`;
      }
    });
    socket.on('event:new', (event) => {
      setEvents((current) => [event, ...current].slice(0, 250));
      if (event.source_ip) loadAttackFeed();
    });
    socket.on('alert:update', (alert) => setAlerts((current) => current.map((item) => (item.id === alert.id ? alert : item))));
    socket.on('alert:delete', (data) => setAlerts((current) => current.filter((item) => item.id !== data.id)));
    socket.on('action:new', (action) => {
      setActions((current) => [action, ...current].slice(0, 100));
      pushConsole(`accion ${action.action_type}: ${action.status}`);
    });
    socket.on('maintenance:purge', () => {
      setAlerts([]);
      setEvents([]);
      setActions([]);
      setNetworkData({ events: [], sources: [], ports: [] });
      setEmailThreats([]);
      pushConsole('registros SIEM limpiados');
      load();
    });
    socket.on('blocked_ip:update', () => load());
    return () => socket.close();
  }, []);

  const filteredAlerts = useMemo(() => {
    return alerts
      .filter((alert) => severity === 'all' || alert.severity === severity)
      .filter((alert) => {
        const needle = query.trim().toLowerCase();
        if (!needle) return true;
        return JSON.stringify(alert).toLowerCase().includes(needle);
      })
      .sort((a, b) => (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0));
  }, [alerts, query, severity]);

  const suspiciousEvents = useMemo(() => {
    return events.filter((event) => /powershell|encoded|rundll32|regsvr32|mshta|failed|4625/i.test(JSON.stringify(event)));
  }, [events]);

  const criticalAlerts = useMemo(() => {
    return alerts.filter((alert) => ['critical', 'high'].includes(alert.severity));
  }, [alerts]);

  const activeAlarm = useMemo(() => {
    return criticalAlerts.some((alert) => new Date(alert.created_at).getTime() > alarmAckAt);
  }, [criticalAlerts, alarmAckAt]);

  useEffect(() => {
    if (!activeAlarm) document.title = 'SOCSentinel Pro';
  }, [activeAlarm]);

  async function demo(kind = 'powershell') {
    if (kind === 'portscan') {
      const ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389, 5985];
      const scanEvents = ports.map((port) => ({
        eventId: 9001,
        provider: 'Windows Firewall',
        hostname: 'PC-HERNAN',
        sourceIp: '192.168.1.77',
        destinationIp: '192.168.1.10',
        sourcePort: 44000 + port,
        destinationPort: port,
        protocol: 'TCP',
        action: 'DROP',
        rawMessage: `DROP TCP 192.168.1.77 192.168.1.10 ${44000 + port} ${port}`,
        timestamp: new Date().toISOString(),
      }));
      await fetch(`${API}/api/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scanEvents),
      });
      pushConsole('evento demo enviado: port scan');
      load();
      return;
    }
    if (kind === 'brute') {
      const burst = Array.from({ length: 5 }, (_, index) => ({
        eventId: 4625,
        hostname: 'PC-HERNAN',
        username: 'admin',
        sourceIp: '192.168.1.66',
        provider: 'Security',
        rawMessage: `An account failed to log on ${index + 1}`,
        timestamp: new Date().toISOString(),
      }));
      burst.push({
        eventId: 4624,
        hostname: 'PC-HERNAN',
        username: 'admin',
        sourceIp: '192.168.1.66',
        provider: 'Security',
        rawMessage: 'An account was successfully logged on after failures',
        timestamp: new Date().toISOString(),
      });
      await fetch(`${API}/api/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(burst),
      });
      pushConsole('evento demo enviado: fuerza bruta con login exitoso');
      load();
      return;
    }
    const samples = {
      powershell: {
        eventId: 4688,
        hostname: 'PC-HERNAN',
        username: 'Hernan',
        process: 'powershell.exe',
        commandLine: 'powershell.exe -enc SQBFAFgA',
        sourceIp: '192.168.1.50',
        provider: 'Security',
      },
      service: {
        eventId: 7045,
        hostname: 'PC-HERNAN',
        username: 'SYSTEM',
        process: 'evilsvc.exe',
        filePath: 'C:\\Temp\\evilsvc.exe',
        provider: 'Service Control Manager',
        rawMessage: 'A service was installed in the system',
      },
    };
    await fetch(`${API}/api/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...samples[kind], timestamp: new Date().toISOString() }),
    });
    pushConsole(`evento demo enviado: ${kind}`);
    load();
  }

  async function action(type, target, alertId) {
    if (!target) return;
    const ok = confirm(`Confirmar accion real: ${type} sobre ${target}\n\nEsto puede modificar Windows si el backend esta en modo respuesta real.`);
    if (!ok) return;
    const result = await fetch(`${API}/api/actions/${type}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, alertId, secret }),
    }).then((response) => response.json());
    pushConsole(`${type} -> ${result.status || result.error}`);
    alert(`Resultado: ${result.status || 'error'}\n${result.output || result.error || ''}`);
    load();
  }

  async function updateAlert(id, status) {
    await fetch(`${API}/api/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    pushConsole(`alerta ${id.slice(0, 8)} marcada como ${status}`);
    load();
  }


  async function classifyAlert(alert, classification, status = 'closed') {
    const analyst_notes = prompt('Nota del analista SOC para esta clasificacion:', alert.analyst_notes || '');
    if (analyst_notes === null) return;
    const result = await fetch(`${API}/api/alerts/${alert.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ classification, status, analyst_notes }),
    }).then((response) => response.json());
    pushConsole(`alerta ${alert.id.slice(0, 8)} clasificada como ${classificationLabels[classification] || classification}`);
    setDetails((current) => current?.data?.id === alert.id ? { ...current, data: result } : current);
    load();
  }

  async function removeAlert(id) {
    if (!confirm('Esto borra la alerta del SIEM, no elimina malware ni evidencia del equipo.')) return;
    await fetch(`${API}/api/alerts/${id}`, { method: 'DELETE' });
    pushConsole(`alerta ${id.slice(0, 8)} eliminada del SIEM`);
  }

  async function purgeAll() {
    if (!confirm('Esto limpiara eventos, alertas, acciones e incidentes guardados en SOCSentinel. No desbloquea IPs, no toca Windows y no borra malware.')) return;
    const result = await fetch(`${API}/api/maintenance/purge`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret }),
    }).then((response) => response.json());
    if (result.ok) {
      pushConsole('registros SIEM limpiados');
      load();
    } else {
      alert(result.error || 'No se pudo limpiar registros');
    }
  }

  async function analyzeEmail() {
    if (!emailRaw.trim()) return;
    const result = await fetch(`${API}/api/email/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawEmail: emailRaw }),
    }).then((response) => response.json());
    if (result.ok) {
      pushConsole(`email analizado: ${result.analysis.severity} score ${result.analysis.score}`);
      setEmailRaw('');
      load();
    } else {
      alert(result.error || 'No se pudo analizar correo');
    }
  }

  async function loadEmailFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    setEmailRaw(await file.text());
  }

  async function loadAttackFeed() {
    const nextAttacks = await getJson('/api/attacks', []);
    setAttacks(nextAttacks);
  }

  async function inspectIp(ip) {
    if (!ip) return;
    const [intel, nextTimeline] = await Promise.all([
      getJson(`/api/ip/${encodeURIComponent(ip)}/intel`, null),
      getJson(`/api/timeline?ip=${encodeURIComponent(ip)}&minutes=240`, []),
    ]);
    setSelectedIntel(intel);
    setTimeline(nextTimeline);
    setActive('map');
  }

  async function inspectAlert(alert) {
    const target = alert?.source_ip || '';
    const nextTimeline = await getJson(`/api/timeline?alertId=${encodeURIComponent(alert.id)}&minutes=240`, []);
    setTimeline(nextTimeline);
    if (target) setSelectedIntel(await getJson(`/api/ip/${encodeURIComponent(target)}/intel`, null));
    setActive('map');
  }

  async function refreshDefender() {
    const nextDefender = await getJson('/api/defender/status', null);
    setDefender(nextDefender);
    if (nextDefender?.ok) {
      pushConsole(`defender actualizado: ${nextDefender.summary?.activeThreats ?? 0} amenazas activas`);
      load();
    } else {
      alert(nextDefender?.error || 'No se pudo consultar Microsoft Defender');
    }
  }

  async function clearHandledDefender() {
    if (!confirm('Esto limpia de la vista SOCSentinel las detecciones Defender ya manejadas. Las amenazas activas seguiran visibles y no se toca la cuarentena real.')) return;
    const result = await fetch(`${API}/api/defender/clear-handled`, { method: 'POST' }).then((response) => response.json());
    if (result.ok) {
      setDefender(result.defender);
      pushConsole(`defender limpio: ${result.hidden} detecciones manejadas ocultadas`);
      load();
    } else {
      alert(result.error || 'No se pudo limpiar Defender');
    }
  }

  const totals = {
    events: events.length,
    alerts: alerts.length,
    critical: alerts.filter((item) => ['critical', 'high'].includes(item.severity)).length,
    actions: actions.length,
  };
  const activeAttacks = useMemo(() => attacks.filter((attack) => attack.is_attack), [attacks]);

  if (!session) {
    return (
      <main className="login-shell">
        <form className="login-panel" onSubmit={login}>
          <div className="brand login-brand">
            <Shield size={30} />
            <div>
              <strong>SOCSentinel</strong>
              <span>Secure analyst login</span>
            </div>
          </div>
          <label>
            Usuario
            <input value={loginForm.username} onChange={(event) => setLoginForm({ ...loginForm, username: event.target.value })} autoComplete="username" />
          </label>
          <label>
            Contraseña
            <input type="password" value={loginForm.password} onChange={(event) => setLoginForm({ ...loginForm, password: event.target.value })} autoComplete="current-password" />
          </label>
          {loginError && <p className="login-error">{loginError}</p>}
          <button className="tool" type="submit">
            <ShieldCheck size={16} />
            Ingresar
          </button>
        </form>
      </main>
    );
  }

  return (
    <main className={activeAlarm ? 'shell alarm-mode' : 'shell'}>
      <aside className="rail">
        <div className="brand">
          <Shield size={28} />
          <div>
            <strong>SOCSentinel</strong>
            <span>Pro SIEM Console</span>
          </div>
        </div>
        <nav>
          {modules.map(({ id, label, icon: Icon }) => (
            <button key={id} className={active === id ? 'nav active' : 'nav'} onClick={() => setActive(id)}>
              <Icon size={18} />
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="system">
          <span className={health?.ok ? 'dot ok' : 'dot'} />
          <div>
            <strong>{health?.ok ? 'API online' : 'API sin enlace'}</strong>
            <small>{health?.mode || 'esperando backend'}</small>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Centro de operaciones defensivas</p>
            <h1>SIEM local para Windows, Sysmon, eventos, alertas y respuesta</h1>
          </div>
          <div className="top-actions">
            <button className="tool" onClick={logout}>Salir</button>
            <input value={secret} onChange={(event) => setSecret(event.target.value)} placeholder="Shared secret" />
            <button className="icon-btn" onClick={load} title="Actualizar">
              <RefreshCw size={18} />
            </button>
          </div>
        </header>

        <section className="stats">
          <Stat icon={Database} label="Eventos" value={totals.events ?? 0} />
          <Stat icon={AlertTriangle} label="Alertas" value={totals.alerts ?? 0} tone="amber" />
          <Stat icon={ShieldAlert} label="Criticas/Altas" value={totals.critical ?? 0} tone="red" />
          <Stat icon={Activity} label="Acciones" value={totals.actions ?? 0} tone="cyan" />
        </section>

        {health?.responseActions && (
          <div className="live-response">
            <ShieldAlert size={16} />
            Respuesta real activa: los botones ejecutan scripts defensivos cuando el secreto coincide.
          </div>
        )}

        {activeAlarm && (
          <div className="critical-banner">
            <ShieldAlert size={20} />
            <div>
              <strong>ALERTA CRITICA ACTIVA</strong>
              <span>{criticalAlerts[0]?.title || 'Actividad de alto riesgo detectada'} {alertOrigin(criticalAlerts[0]) !== '-' ? `desde ${alertOrigin(criticalAlerts[0])}` : ''}</span>
            </div>
            <button className="tool danger" onClick={() => setAlarmAckAt(Date.now())}>
              Silenciar
            </button>
          </div>
        )}

        {active === 'command' && (
          <section className="layout two">
            <div className="panel terminal-panel">
              <div className="panel-head">
                <h2>Consola SOC</h2>
                <span>flujo en tiempo real</span>
              </div>
              <div className="terminal">
                {consoleLines.map((line, index) => (
                  <p key={`${line}-${index}`}>{line}</p>
                ))}
              </div>
              <div className="quick-grid">
                <ActionButton icon={RefreshCw} label="Actualizar" onClick={load} />
                <ActionButton icon={Trash2} label="Limpiar SIEM" danger onClick={purgeAll} />
              </div>
            </div>
            <div className="panel">
              <div className="panel-head">
                <h2>Radar de riesgo</h2>
                <span>hosts y senales</span>
              </div>
              <div className={activeAlarm ? 'radar radar-danger' : 'radar'}>
                <Radar size={120} />
                <div>
                  <strong>{filteredAlerts.length}</strong>
                  <span>alertas visibles</span>
                </div>
              </div>
              <div className="mini-list">
                {filteredAlerts.slice(0, 6).map((alert) => (
                  <button key={alert.id} onClick={() => setActive('alerts')}>
                    <span className={clsSeverity(alert.severity)}>{alert.severity}</span>
                    <b>{alert.hostname || 'unknown'}</b>
                    <small>{alert.title}</small>
                  </button>
                ))}
              </div>
            </div>
          </section>
        )}

        {active === 'alerts' && (
          <section className="panel">
            <div className="panel-head controls">
              <h2>Alertas en tiempo real</h2>
              <div>
                <Filter size={16} />
                <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
                  <option value="all">Todas</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
                <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Buscar host, usuario, IP, proceso" />
              </div>
            </div>
            <div className="alert-list">
              {filteredAlerts.map((alert) => (
                <article className="alert" key={alert.id}>
                  <div className="alert-main">
                    <span className={clsSeverity(alert.severity)}>{alert.severity}</span>
                    <div>
                      <h3>{alert.title}</h3>
                      <p>{alert.recommendation}</p>
                    </div>
                  </div>
                  <dl>
                    {isEmailAlert(alert) ? (
                      <>
                        <div><dt>Remitente</dt><dd>{alert.email_sender || alert.evidence?.sender || '-'}</dd></div>
                        <div><dt>Destinatario</dt><dd>{alert.email_recipient || alert.evidence?.recipient || '-'}</dd></div>
                        <div><dt>Asunto</dt><dd>{shortText(alert.email_subject || alert.evidence?.subject, 70)}</dd></div>
                        <div><dt>Score</dt><dd>{alert.email_score ?? alert.evidence?.score ?? '-'}</dd></div>
                        <div><dt>MITRE</dt><dd>{alert.mitre || '-'}</dd></div>
                        <div><dt>Estado</dt><dd>{alert.status || 'new'}</dd></div>
                        <div><dt>Clasificacion</dt><dd>{classificationLabels[alert.classification] || alert.classification || 'Sin clasificar'}</dd></div>
                      </>
                    ) : (
                      <>
                        <div><dt>Host</dt><dd>{alert.hostname || '-'}</dd></div>
                        <div><dt>Usuario</dt><dd>{alert.username || '-'}</dd></div>
                        <div><dt>Proceso</dt><dd>{shortText(alert.process, 70)}</dd></div>
                        <div><dt>IP</dt><dd>{alert.source_ip || '-'}</dd></div>
                        <div><dt>MITRE</dt><dd>{alert.mitre || '-'}</dd></div>
                        <div><dt>Estado</dt><dd>{alert.status || 'new'}</dd></div>
                        <div><dt>Clasificacion</dt><dd>{classificationLabels[alert.classification] || alert.classification || 'Sin clasificar'}</dd></div>
                      </>
                    )}
                  </dl>
                  <div className="buttons">
                    <ActionButton icon={Eye} label="En investigacion" onClick={() => classifyAlert(alert, 'needs_review', 'investigating')} />
                    <ActionButton icon={ShieldCheck} label="True positive" onClick={() => classifyAlert(alert, 'true_positive', 'confirmed')} />
                    <ActionButton icon={Shield} label="False positive" onClick={() => classifyAlert(alert, 'false_positive', 'closed')} />
                    <ActionButton icon={Eye} label="Benigno real" onClick={() => classifyAlert(alert, 'benign_true_positive', 'closed')} />
                    <ActionButton icon={MapPin} label="Rastrear" onClick={() => inspectAlert(alert)} />
                    <ActionButton icon={Ban} label="Bloquear IP" onClick={() => action('block_ip', alert.source_ip, alert.id)} disabled={!alert.source_ip || isEmailAlert(alert)} />
                    <ActionButton icon={Ban} label="Bloquear puerto" onClick={() => action('block_port', alertPort(alert), alert.id)} disabled={!alertPort(alert) || isEmailAlert(alert)} />
                    <ActionButton icon={WifiOff} label="Aislar host" onClick={() => action('isolate_host', alert.hostname, alert.id)} disabled={isEmailAlert(alert)} />
                    <ActionButton icon={FileSearch} label="Ubicar malware" onClick={() => action('locate_malware', fileTarget(alert), alert.id)} disabled={!fileTarget(alert)} />
                    <ActionButton icon={ScanLine} label="Defender" onClick={() => action('defender_scan', scanTarget(alert), alert.id)} />
                    <ActionButton icon={Trash2} label="Matar proceso" danger onClick={() => action('kill_process', fileTarget(alert), alert.id)} disabled={!fileTarget(alert) || isEmailAlert(alert)} />
                    <ActionButton icon={FileSearch} label="Cuarentena" danger onClick={() => action('quarantine_file', fileTarget(alert), alert.id)} disabled={!fileTarget(alert) || isEmailAlert(alert)} />
                    <ActionButton icon={Trash2} label="Remediar" danger onClick={() => action('remove_malware', fileTarget(alert), alert.id)} disabled={!fileTarget(alert)} />
                    <ActionButton icon={FileText} label="Reporte" onClick={() => action('generate_report', alert.source_ip || alert.id, alert.id)} />
                    <ActionButton icon={Trash2} label="Borrar alerta" onClick={() => removeAlert(alert.id)} />
                    <ActionButton icon={Eye} label="Ver mas" onClick={() => setDetails({ type: 'Alerta', data: alert })} />
                  </div>
                </article>
              ))}
            </div>
          </section>
        )}

        {active === 'events' && (
          <section className="panel">
            <div className="panel-head">
              <h2>Visor de eventos Windows/Sysmon</h2>
              <span>Security, Sysmon, Service Control Manager</span>
            </div>
            <div className="event-table">
              <div className="event-row head"><span>Hora</span><span>ID</span><span>Host</span><span>Usuario</span><span>Proceso</span><span>IP</span></div>
              {events.slice(0, 120).map((event) => (
                <div className="event-row" key={event.id}>
                  <span>{formatTime(event.created_at)}</span>
                  <span>{event.event_id}</span>
                  <span>{event.hostname || '-'}</span>
                  <span>{event.username || '-'}</span>
                  <span>{shortText(event.process, 70)}</span>
                  <span>{event.source_ip || '-'}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {active === 'network' && (
          <section className="layout two">
            <div className="panel">
              <div className="panel-head">
                <h2>Network IDS / Firewall</h2>
                <span>escaneos, puertos y fuentes</span>
              </div>
              <div className="buttons">
                <ActionButton icon={Network} label="Activar logging Firewall" onClick={() => action('enable_firewall_logging', 'local', null)} />
                <ActionButton icon={WifiOff} label="Desactivar logging" onClick={() => action('disable_firewall_logging', 'local', null)} />
                <ActionButton icon={Trash2} label="Limpiar registros" danger onClick={purgeAll} />
              </div>
              <div className="network-grid">
                <div>
                  <h3>Fuentes recientes</h3>
                  {networkData.sources.map((source) => (
                    <article className="network-item" key={source.source_ip}>
                      <strong>{source.source_ip}</strong>
                      <span className={source.is_attack ? 'severity high' : 'severity info'}>{source.is_attack ? 'IDS scan' : 'observado'}</span>
                      <span>{source.attempts} intentos / {source.ports} puertos</span>
                      <small>{formatTime(source.last_seen)}</small>
                      {source.is_attack && (
                        <ActionButton icon={Ban} label="Bloquear IP" onClick={() => action('block_ip', source.source_ip, null)} />
                      )}
                    </article>
                  ))}
                </div>
                <div>
                  <h3>IPs bloqueadas</h3>
                  {blockedIps.map((item) => (
                    <article className="network-item" key={item.ip}>
                      <strong>{item.ip}</strong>
                      <span>{item.reason || 'manual'}</span>
                      <small>{formatTime(item.updated_at)}</small>
                      <ActionButton icon={LockOpen} label="Desbloquear IP" onClick={() => action('unblock_ip', item.ip, null)} />
                    </article>
                  ))}
                  <h3>Puertos tocados</h3>
                  {networkData.ports.map((port) => (
                    <article className="network-item compact-line" key={port.destination_port}>
                      <strong>{port.destination_port}</strong>
                      <span>{port.hits} hits</span>
                    </article>
                  ))}
                </div>
              </div>
            </div>
            <div className="panel">
              <div className="panel-head">
                <h2>Eventos de red</h2>
                <span>ultimos 200</span>
              </div>
              <div className="network-events">
                {networkData.events.slice(0, 40).map((event) => (
                  <button className="network-event" key={event.id} onClick={() => setDetails({ type: 'Evento de red', data: event })}>
                    <strong>{event.source_ip || '-'}</strong>
                    <span>{event.protocol || 'IP'} {event.destination_ip || '-'}:{event.destination_port || '-'}</span>
                    <small>{formatTime(event.created_at)}</small>
                  </button>
                ))}
              </div>
            </div>
          </section>
        )}

        {active === 'map' && (
          <section className="layout two">
            <div className="panel">
              <div className="panel-head">
                <h2>Mapa de ataques en tiempo real</h2>
                <span>IP origen, reputacion y destino local</span>
              </div>
              <div className="attack-map">
                <div className="globe">
                  <div className="globe-grid" />
                  {activeAttacks.slice(0, 18).map((attack, index) => {
                    const top = 12 + (Math.abs(Number(attack.intel?.latitude || 0)) % 68);
                    const left = 8 + (Math.abs(Number(attack.intel?.longitude || 0)) % 84);
                    const homeTop = 86;
                    const homeLeft = 50;
                    const dx = homeLeft - left;
                    const dy = homeTop - top;
                    const length = Math.sqrt(dx * dx + dy * dy);
                    const angle = Math.atan2(dy, dx) * (180 / Math.PI);
                    return (
                      <React.Fragment key={attack.source_ip}>
                        <span
                          className={`attack-beam ${attack.severity || 'info'}`}
                          style={{
                            top: `${top}%`,
                            left: `${left}%`,
                            width: `${length}%`,
                            transform: `rotate(${angle}deg)`,
                            animationDelay: `${index * 0.14}s`,
                          }}
                        />
                        <button
                          className={`attack-dot ${attack.severity || 'info'}`}
                          style={{ top: `${top}%`, left: `${left}%`, animationDelay: `${index * 0.12}s` }}
                          title={`${attack.source_ip} ${attack.intel?.country || ''}`}
                          onClick={() => inspectIp(attack.source_ip)}
                        />
                      </React.Fragment>
                    );
                  })}
                  <div className={activeAttacks.length ? 'home-node under-attack' : 'home-node'}>
                    <Shield size={18} />
                    <span>PC-HERNAN</span>
                  </div>
                </div>
              </div>
              <div className="attack-feed">
                {attacks.slice(0, 12).map((attack) => (
                  <button className="attack-row" key={attack.source_ip} onClick={() => inspectIp(attack.source_ip)}>
                    <span className={clsSeverity(attack.severity)}>{attack.severity}</span>
                    <strong>{attack.source_ip}</strong>
                    <span>{attack.intel?.city || '-'}, {attack.intel?.country || '-'}</span>
                    <small>{attack.attempts} intentos / {attack.ports} puertos / {formatTime(attack.last_seen)}</small>
                  </button>
                ))}
              </div>
            </div>
            <div className="panel">
              <div className="panel-head">
                <h2>Rastreo de ataque</h2>
                <span>timeline forense</span>
              </div>
              {selectedIntel ? (
                <div className="intel-card">
                  <MapPin size={18} />
                  <strong>{selectedIntel.ip}</strong>
                  <span>{selectedIntel.city || '-'}, {selectedIntel.country || '-'}</span>
                  <small>{selectedIntel.asn || '-'} / {selectedIntel.isp || '-'}</small>
                  <small>Reputacion {selectedIntel.reputation_score ?? 0} / fuente {selectedIntel.source || 'local'}</small>
                </div>
              ) : (
                <div className="intel-card">
                  <MapPin size={18} />
                  <strong>Selecciona una IP</strong>
                  <span>El timeline aparecera aqui.</span>
                </div>
              )}
              <div className="timeline">
                {timeline.slice(0, 40).map((item) => (
                  <button className="timeline-item" key={`${item.kind}-${item.id}`} onClick={() => setDetails({ type: 'Timeline', data: item })}>
                    <span className={clsSeverity(item.severity)}>{item.kind}</span>
                    <strong>{item.title || item.code}</strong>
                    <small>{formatTime(item.created_at)} / {item.hostname || '-'} / {item.process || '-'}</small>
                    <small>{item.source_ip || '-'} {item.destination_port ? `:${item.destination_port}` : ''}</small>
                  </button>
                ))}
              </div>
            </div>
          </section>
        )}

        {active === 'email' && (
          <section className="layout two">
            <div className="panel">
              <div className="panel-head">
                <h2>Email Threat Monitor</h2>
                <span>phishing, URLs y adjuntos</span>
              </div>
              <div className="email-tools">
                <input type="file" accept=".eml,.txt" onChange={loadEmailFile} />
                <button className="tool" onClick={analyzeEmail} disabled={!emailRaw.trim()}>
                  <Mail size={16} />
                  Analizar correo
                </button>
              </div>
              <textarea
                className="email-input"
                value={emailRaw}
                onChange={(event) => setEmailRaw(event.target.value)}
                placeholder="Pega aqui el contenido completo del correo o carga un archivo .eml"
              />
            </div>
            <div className="panel">
              <div className="panel-head">
                <h2>Correos analizados</h2>
                <span>evidencia reciente</span>
              </div>
              <div className="email-list">
                {emailThreats.map((item) => (
                  <button className="email-item" key={item.id} onClick={() => setDetails({ type: 'Analisis de correo', data: item })}>
                    <span className={clsSeverity(item.severity)}>{item.severity}</span>
                    <strong>{shortText(item.subject, 80)}</strong>
                    <small>{item.sender || '-'} / score {item.score} / {item.raw?.analysis?.verdict || item.severity}</small>
                  </button>
                ))}
              </div>
            </div>
          </section>
        )}

        {active === 'defender' && (
          <section className="layout two">
            <div className="panel">
              <div className="panel-head">
                <h2>Microsoft Defender SOC L2</h2>
                <span>estado, firmas, amenazas y respuesta</span>
              </div>
              <div className="buttons">
                <ActionButton icon={RefreshCw} label="Actualizar Defender" onClick={refreshDefender} />
                <ActionButton icon={Trash2} label="Limpiar manejadas" onClick={clearHandledDefender} />
                <ActionButton icon={ScanLine} label="QuickScan" onClick={() => action('defender_scan', 'QuickScan', null)} />
                <ActionButton icon={ScanLine} label="FullScan" onClick={() => action('defender_scan', 'FullScan', null)} />
              </div>
              {defender && !defender.ok && (
                <div className="defender-warning">
                  <ShieldAlert size={16} />
                  <span>Defender requiere backend como administrador: {shortText(defender.error, 180)}</span>
                </div>
              )}
              <div className="defender-grid">
                <article className={defender?.summary?.protectionHealthy ? 'defender-card ok' : 'defender-card danger'}>
                  <span>Proteccion</span>
                  <strong>{defender?.summary?.protectionHealthy ? 'Activa' : 'Revisar'}</strong>
                  <small>Realtime {defender?.engine?.realTimeProtectionEnabled ? 'ON' : 'OFF'} / AV {defender?.engine?.antivirusEnabled ? 'ON' : 'OFF'}</small>
                </article>
                <article className={defender?.summary?.activeThreats > 0 ? 'defender-card danger' : 'defender-card ok'}>
                  <span>Amenazas activas</span>
                  <strong>{defender?.summary?.activeThreats ?? '-'}</strong>
                  <small>{defender?.summary?.totalDetections ?? 0} visibles / {defender?.summary?.hiddenHandledDetections ?? 0} ocultas</small>
                </article>
                <article className="defender-card">
                  <span>Firmas AV</span>
                  <strong>{defender?.engine?.antivirusSignatureAge ?? '-'}</strong>
                  <small>{shortText(defender?.engine?.antivirusSignatureVersion, 44)}</small>
                </article>
                <article className="defender-card">
                  <span>Ultimo QuickScan</span>
                  <strong>{defender?.engine?.quickScanAge ?? '-'}</strong>
                  <small>{formatTime(defender?.engine?.lastQuickScan)}</small>
                </article>
              </div>
              <div className="defender-section">
                <h3>Configuracion sensible</h3>
                <div className="defender-kv">
                  <span>Behavior Monitor</span><strong>{defender?.engine?.behaviorMonitorEnabled ? 'ON' : 'OFF'}</strong>
                  <span>IOAV</span><strong>{defender?.engine?.ioavProtectionEnabled ? 'ON' : 'OFF'}</strong>
                  <span>Tamper Protection</span><strong>{defender?.engine?.tamperProtection || '-'}</strong>
                  <span>Cloud Block</span><strong>{defender?.preferences?.cloudBlockLevel || '-'}</strong>
                  <span>Exclusiones path</span><strong>{defender?.preferences?.exclusionPath?.length ?? 0}</strong>
                  <span>Exclusiones proceso</span><strong>{defender?.preferences?.exclusionProcess?.length ?? 0}</strong>
                </div>
              </div>
            </div>
            <div className="panel">
              <div className="panel-head">
                <h2>Detecciones Defender</h2>
                <span>evidencia real</span>
              </div>
              <div className="defender-list">
                {(defender?.detections || []).map((item, index) => (
                  <button className="defender-item" key={`${item.threatId}-${index}`} onClick={() => setDetails({ type: 'Deteccion Defender', data: item })}>
                    <span className={item.actionSuccess ? 'severity medium' : 'severity critical'}>{item.actionSuccess ? 'handled' : 'active'}</span>
                    <strong>{item.threatName || `Threat ${item.threatId}`}</strong>
                    <small>{shortText((item.resources || []).join(' '), 110)}</small>
                    <small>{formatTime(item.initialDetectionTime)}</small>
                  </button>
                ))}
                {!(defender?.detections || []).length && (
                  <article className="defender-item empty">
                    <strong>Sin detecciones recientes</strong>
                    <small>Defender no reporto amenazas en esta consulta.</small>
                  </article>
                )}
              </div>
            </div>
          </section>
        )}

        {active === 'hunt' && (
          <section className="layout two">
            <div className="panel">
              <div className="panel-head">
                <h2>Threat hunting</h2>
                <span>eventos sospechosos derivados</span>
              </div>
              <div className="hunt-list">
                {suspiciousEvents.slice(0, 30).map((event) => (
                  <pre key={event.id}>{JSON.stringify({ id: event.event_id, host: event.hostname, user: event.username, process: event.process, ip: event.source_ip }, null, 2)}</pre>
                ))}
              </div>
            </div>
            <div className="panel">
              <div className="panel-head">
                <h2>Consultas rapidas</h2>
                <span>patrones SIEM</span>
              </div>
              {['powershell -enc', 'event_id:4625', 'admin success after failures', 'new service installed', 'sysmon network'].map((item) => (
                <button className="query-btn" key={item} onClick={() => setQuery(item)}>
                  <Search size={16} />
                  {item}
                </button>
              ))}
            </div>
          </section>
        )}

        {active === 'malware' && (
          <section className="panel">
            <div className="panel-head">
              <h2>Investigacion de malware</h2>
              <span>localizacion, escaneo y remediacion manual</span>
            </div>
            <div className="malware-grid">
              {filteredAlerts.slice(0, 12).map((alert) => (
                <article className="malware-card" key={alert.id}>
                  <span className={clsSeverity(alert.severity)}>{alert.severity}</span>
                  <h3>{alert.process || alert.file_path || alert.title}</h3>
                  <p>{alert.hostname || '-'} / {alert.username || '-'}</p>
                  <div className="buttons compact">
                    <ActionButton icon={FileSearch} label="Ubicar" onClick={() => action('locate_malware', fileTarget(alert), alert.id)} disabled={!fileTarget(alert)} />
                    <ActionButton icon={ScanLine} label="Escanear" onClick={() => action('defender_scan', scanTarget(alert), alert.id)} />
                    <ActionButton icon={Trash2} label="Remediar" danger onClick={() => action('remove_malware', fileTarget(alert), alert.id)} disabled={!fileTarget(alert)} />
                  </div>
                </article>
              ))}
            </div>
          </section>
        )}

        {active === 'response' && (
          <section className="panel">
            <div className="panel-head">
              <h2>Historial de respuesta</h2>
              <span>auditoria y ejecuciones</span>
            </div>
            <div className="event-table actions-table">
              <div className="event-row head"><span>Hora</span><span>Accion</span><span>Target</span><span>Estado</span><span>Salida</span></div>
              {actions.map((item) => (
                <div className="event-row" key={item.id}>
                  <span>{formatTime(item.created_at)}</span>
                  <span>{item.action_type}</span>
                  <span>{item.target}</span>
                  <span>{item.status}</span>
                  <span>{shortText(item.output, 120)}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {details && (
          <div className="modal-backdrop" onClick={() => setDetails(null)}>
            <section className="modal" onClick={(event) => event.stopPropagation()}>
              <div className="panel-head">
                <h2>{details.type}</h2>
                <button className="icon-btn" onClick={() => setDetails(null)}>Cerrar</button>
              </div>
              {details.type === 'Alerta' && (
                <div className="triage-panel">
                  <span className="triage-pill">{classificationLabels[details.data.classification] || details.data.classification || 'Sin clasificar'}</span>
                  <button onClick={() => classifyAlert(details.data, 'true_positive', 'confirmed')}>True positive</button>
                  <button onClick={() => classifyAlert(details.data, 'false_positive', 'closed')}>False positive</button>
                  <button onClick={() => classifyAlert(details.data, 'benign_true_positive', 'closed')}>Benigno real</button>
                  <button onClick={() => classifyAlert(details.data, 'needs_review', 'investigating')}>En revision</button>
                </div>
              )}
              {details.type === 'Analisis de correo' && (
                <div className="phishing-verdict">
                  <strong>{details.data.raw?.analysis?.verdict || details.data.severity}</strong>
                  <span>{details.data.raw?.analysis?.authVerdict || 'cabeceras no concluyentes'}</span>
                  <small>{details.data.raw?.analysis?.recommendedAction || 'Revisar evidencia del correo.'}</small>
                </div>
              )}
              <pre>{prettyJson(details.data)}</pre>
            </section>
          </div>
        )}
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);

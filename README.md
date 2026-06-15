# SOCSentinel Pro V3

SIEM/SOC local defensivo para laboratorio Windows, con monitoreo en tiempo real, investigacion SOC L2, respuesta manual y trazabilidad forense.

## Qué incluye

- Backend Node.js + Express
- PostgreSQL
- WebSocket en tiempo real con Socket.IO
- Frontend React + Vite
- Agente Windows Node.js para leer Windows Event Logs y Sysmon
- Motor de reglas SIEM
- Correlación básica SOC
- Dashboard de eventos y alertas
- Mapa visual de ataques en tiempo real
- Inteligencia/reputacion de IP local y opcional con AbuseIPDB
- Timeline forense por alerta o IP
- Analisis de phishing desde correos `.eml`
- Integracion con Microsoft Defender
- Botones manuales defensivos:
  - Bloquear IP
  - Bloquear puerto
  - Aislar equipo local
  - Escanear con Microsoft Defender
  - Ubicar/remediar archivo sospechoso
  - Generar reporte de incidente
  - Eliminar alerta del SIEM

## Importante

- Nada se ejecuta automáticamente.
- Las acciones reales están desactivadas por defecto.
- El botón `Eliminar alerta SIEM` borra la alerta de la base de datos, NO elimina malware del PC.
- Para malware real: aislar, recolectar evidencia, escanear, cuarentena y recién después eliminar con herramientas seguras.

## Requisitos

- Windows 11
- Node.js LTS
- PostgreSQL
- PowerShell como administrador para el agente y scripts defensivos
- Sysmon recomendado

## Configuracion

Copia el ejemplo y ajusta tu clave local:

```powershell
copy backend\.env.example backend\.env
```

Variables principales:

```env
PORT=4000
DATABASE_URL=postgres://postgres:TU_PASSWORD@127.0.0.1:5432/socsentinel
ALLOW_RESPONSE_ACTIONS=false
RESPONSE_SHARED_SECRET=pon-una-clave-larga
```

Opcional para reputacion IP:

```env
ABUSEIPDB_API_KEY=tu_api_key
```

El archivo `backend/.env` no se sube al repositorio.

## Instalación rápida

### 1. Crear base de datos PostgreSQL

```sql
CREATE DATABASE socsentinel;
```

Luego:

```powershell
cd backend
copy .env.example .env
npm install
npm run db:init
npm run dev
```

Backend:

```txt
http://localhost:4000
```

### 2. Ejecutar frontend

```powershell
cd frontend
npm install
npm run dev
```

Abrir:

```txt
http://localhost:5173
```

### 3. Ejecutar agente Windows

En PowerShell como administrador:

```powershell
cd agent-windows
npm install
npm start
```

El agente lee eventos relevantes de:

- Security
- Microsoft-Windows-Sysmon/Operational

Eventos incluidos:

- 4624 login exitoso
- 4625 login fallido
- 4688 proceso creado
- 4720 usuario creado
- 4724 password reset
- 4732 agregado a grupo
- 7045 servicio instalado
- Sysmon 1 proceso creado
- Sysmon 3 conexión de red
- Sysmon 11 archivo creado

## Activar acciones reales

Por defecto, bloquear IP, aislar host y escanear Defender quedan en modo auditoría.

Para permitir ejecución real, edita `backend/.env`:

```env
ALLOW_RESPONSE_ACTIONS=true
RESPONSE_SHARED_SECRET=pon-una-clave-larga
```

Reinicia backend y usa esa clave en la caja del dashboard.

## Revertir aislamiento

Si aislaste tu equipo por error, abre PowerShell como administrador y ejecuta:

```powershell
Remove-NetFirewallRule -DisplayName "SOCSentinel Isolation*"
```

## Revertir bloqueo de IP

```powershell
Remove-NetFirewallRule -DisplayName "SOCSentinel Block*"
```

## Sysmon

Descarga Sysmon desde Microsoft Sysinternals y ejecútalo como administrador con una configuración segura. Recomendado para obtener procesos, conexiones y creación de archivos.

Ejemplo:

```powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

## Qué falta para versión empresarial

- Instalador como servicio Windows
- Cuarentena EDR completa
- Autenticación con usuarios reales
- Reportes PDF profesionales
- MITRE ATT&CK avanzado
- Timeline forense completo
- Parser EVTX dedicado
- Reglas Sigma/YARA integradas

Esta V3 es una base real para laboratorio doméstico y entrenamiento SOC Nivel 1.


## Guía rápida corregida para Hernan

### Orden correcto de ejecución

Abre 3 ventanas de PowerShell.

#### Ventana 1 - Backend

```powershell
cd C:\RUTA\SOCSentinel-Pro-V3-FIXED
.\start-backend.ps1
```

Si tu PostgreSQL usa otra contraseña, edita `backend\.env`:

```env
DATABASE_URL=postgres://postgres:TU_PASSWORD@localhost:5432/socsentinel
ALLOW_RESPONSE_ACTIONS=false
RESPONSE_SHARED_SECRET=change-this-secret
```

Para crear la base si no existe:

```powershell
psql -U postgres -c "CREATE DATABASE socsentinel;"
```

#### Ventana 2 - Frontend

```powershell
cd C:\RUTA\SOCSentinel-Pro-V3-FIXED
.\start-frontend.ps1
```

Abre: `http://localhost:5173`

#### Ventana 3 - Agente Windows en tiempo real

Abre PowerShell **como Administrador**:

```powershell
cd C:\RUTA\SOCSentinel-Pro-V3-FIXED
.\start-agent-admin.ps1
```

El agente envía eventos reales de Windows/Sysmon al backend.

### Activar botones reales de respuesta

Por defecto está seguro, en modo auditoría:

```env
ALLOW_RESPONSE_ACTIONS=false
```

Eso significa: el botón registra la acción, pero no toca Windows.

Para que los botones ejecuten acciones reales cuando tú los presiones:

```env
ALLOW_RESPONSE_ACTIONS=true
RESPONSE_SHARED_SECRET=pon-una-clave-larga
```

Luego reinicia el backend y escribe la misma clave en la caja del dashboard.

### Importante sobre aislar equipo

El aislamiento crea reglas de firewall que pueden dejar tu equipo sin red. Para revertir:

```powershell
Remove-NetFirewallRule -DisplayName "SOCSentinel Isolation*"
```

### Importante sobre malware

Este SIEM detecta señales sospechosas y puede lanzar escaneo Defender. No promete identificar todo malware ni limpiar infecciones por sí solo. Para sospecha real: desconecta internet, escanea con Microsoft Defender Offline, revisa procesos/autoruns y guarda evidencia.

$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
$BackendDir = Join-Path $Root "backend"
$FrontendDir = Join-Path $Root "frontend"
$AgentDir = Join-Path $Root "agent-windows"

function Test-Port {
  param([int]$Port)
  $line = netstat -ano | Select-String "127.0.0.1:$Port\s+.*LISTENING" | Select-Object -First 1
  return [bool]$line
}

function Get-PortPid {
  param([int]$Port)
  $line = netstat -ano | Select-String "127.0.0.1:$Port\s+.*LISTENING" | Select-Object -First 1
  if (!$line) { return $null }
  $parts = ($line.ToString() -split "\s+") | Where-Object { $_ }
  return [int]$parts[-1]
}

function Ensure-Env {
  param([string]$Dir)
  $envFile = Join-Path $Dir ".env"
  $example = Join-Path $Dir ".env.example"
  if (!(Test-Path $envFile) -and (Test-Path $example)) {
    Copy-Item $example $envFile
  }
}

function Start-SOCWindow {
  param(
    [string]$Title,
    [string]$WorkingDirectory,
    [string]$Command,
    [switch]$RunAsAdmin
  )

  $escapedTitle = $Title.Replace("'", "''")
  $escapedDir = $WorkingDirectory.Replace("'", "''")
  $escapedCommand = $Command.Replace("'", "''")
  $script = "`$Host.UI.RawUI.WindowTitle = '$escapedTitle'; cd '$escapedDir'; $escapedCommand"
  if ($RunAsAdmin) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $script -WorkingDirectory $WorkingDirectory
  } else {
    Start-Process powershell.exe -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $script -WorkingDirectory $WorkingDirectory
  }
}

function Update-DatabaseUrl {
  param([string]$Password)
  $envFile = Join-Path $BackendDir ".env"
  if ([string]::IsNullOrWhiteSpace($Password)) {
    $databaseUrl = "postgres://postgres@localhost:5432/socsentinel"
  } else {
    $encodedPassword = [uri]::EscapeDataString($Password)
    $databaseUrl = "postgres://postgres:$encodedPassword@localhost:5432/socsentinel"
  }
  $content = Get-Content $envFile
  $updated = $false
  $next = foreach ($line in $content) {
    if ($line -match "^DATABASE_URL=") {
      $updated = $true
      "DATABASE_URL=$databaseUrl"
    } else {
      $line
    }
  }
  if (!$updated) {
    $next += "DATABASE_URL=$databaseUrl"
  }
  Set-Content -Path $envFile -Value $next
}

function Initialize-Database {
  Write-Host "Inicializando base de datos..." -ForegroundColor Cyan
  Push-Location $BackendDir
  try {
    npm run db:init
    Pop-Location
    return
  } catch {
    Pop-Location
    Write-Host ""
    Write-Host "No se pudo conectar a PostgreSQL con la configuracion actual." -ForegroundColor Yellow
    Write-Host "Si PostgreSQL no tiene password, presiona Enter sin escribir nada." -ForegroundColor Yellow
    $password = Read-Host "Password PostgreSQL usuario postgres"
    Update-DatabaseUrl -Password $password
    Write-Host "backend\.env actualizado. Reintentando db:init..." -ForegroundColor Cyan
    Push-Location $BackendDir
    npm run db:init
    Pop-Location
  }
}

Write-Host ""
Write-Host "SOCSentinel Pro - Lanzador unificado" -ForegroundColor Cyan
Write-Host "Raiz: $Root" -ForegroundColor DarkGray
Write-Host ""

Ensure-Env $BackendDir
Ensure-Env $AgentDir

if (!(Test-Path (Join-Path $BackendDir "node_modules"))) {
  Write-Host "Instalando dependencias backend..." -ForegroundColor Yellow
  Push-Location $BackendDir
  npm install
  Pop-Location
}

if (!(Test-Path (Join-Path $FrontendDir "node_modules"))) {
  Write-Host "Instalando dependencias frontend..." -ForegroundColor Yellow
  Push-Location $FrontendDir
  npm install
  Pop-Location
}

if (!(Test-Path (Join-Path $AgentDir "node_modules"))) {
  Write-Host "Instalando dependencias agente Windows..." -ForegroundColor Yellow
  Push-Location $AgentDir
  npm install
  Pop-Location
}

Initialize-Database

$envContent = Get-Content (Join-Path $BackendDir ".env") -ErrorAction SilentlyContinue
$realResponse = $envContent -match "^ALLOW_RESPONSE_ACTIONS=true"
if (Test-Port 4000) {
  if ($realResponse) {
    Write-Host "Backend ya esta escuchando en http://localhost:4000" -ForegroundColor Yellow
    $restart = Read-Host "Respuesta real requiere backend como Administrador. Reiniciar backend elevado? (S/N)"
    if ($restart -match "^[sS]") {
      $pid = Get-PortPid 4000
      if ($pid) { Stop-Process -Id $pid -Force }
      Start-Sleep -Seconds 2
      Start-SOCWindow -Title "SOCSentinel Backend API ADMIN" -WorkingDirectory $BackendDir -Command "npm run dev" -RunAsAdmin
    }
  } else {
    Write-Host "Backend ya esta escuchando en http://localhost:4000" -ForegroundColor Green
  }
} else {
  if ($realResponse) {
    Write-Host "Respuesta real activa: el backend se abrira como Administrador." -ForegroundColor Yellow
    Start-SOCWindow -Title "SOCSentinel Backend API ADMIN" -WorkingDirectory $BackendDir -Command "npm run dev" -RunAsAdmin
  } else {
    Start-SOCWindow -Title "SOCSentinel Backend API" -WorkingDirectory $BackendDir -Command "npm run dev"
  }
}

Start-Sleep -Seconds 2

if (Test-Port 5173) {
  Write-Host "Frontend ya esta escuchando en http://127.0.0.1:5173" -ForegroundColor Green
} else {
  Start-SOCWindow -Title "SOCSentinel Frontend Console" -WorkingDirectory $FrontendDir -Command "npm run dev -- --host 127.0.0.1"
}

Write-Host ""
Write-Host "Backend:  http://localhost:4000" -ForegroundColor Green
Write-Host "Consola:  http://127.0.0.1:5173" -ForegroundColor Green
Write-Host ""

$agentAnswer = Read-Host "Quieres iniciar el agente Windows ahora como Administrador? (S/N)"
if ($agentAnswer -match "^[sS]") {
  $agentCommand = "cd '$AgentDir'; npm start"
  Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $agentCommand
  Write-Host "Se solicito una ventana elevada para el agente." -ForegroundColor Yellow
} else {
  Write-Host "Agente omitido. Puedes iniciarlo luego con start-agent-admin.ps1 o desde este launcher." -ForegroundColor Yellow
}

Start-Sleep -Seconds 3
Start-Process "http://127.0.0.1:5173"

Write-Host ""
Write-Host "Listo. Puedes cerrar esta ventana; backend/frontend quedan en sus propias ventanas." -ForegroundColor Cyan

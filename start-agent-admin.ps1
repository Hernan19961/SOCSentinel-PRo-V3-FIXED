Write-Host "Starting SOCSentinel Windows Agent..." -ForegroundColor Cyan
Write-Host "Run this PowerShell window as Administrator for Security/Sysmon logs." -ForegroundColor Yellow
Set-Location "$PSScriptRoot\agent-windows"
if (!(Test-Path .env)) { Copy-Item .env.example .env; Write-Host "Created agent-windows\.env from example." -ForegroundColor Yellow }
npm install
npm start

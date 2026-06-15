Write-Host "Starting SOCSentinel backend..." -ForegroundColor Cyan
Set-Location "$PSScriptRoot\backend"
if (!(Test-Path .env)) { Copy-Item .env.example .env; Write-Host "Created backend\.env from example. Edit DATABASE_URL if needed." -ForegroundColor Yellow }
npm install
npm run db:init
npm run dev

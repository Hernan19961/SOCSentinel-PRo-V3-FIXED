Write-Host "Starting SOCSentinel frontend..." -ForegroundColor Cyan
Set-Location "$PSScriptRoot\frontend"
npm install
npm run dev

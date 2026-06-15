param([string]$Root = (Resolve-Path "$PSScriptRoot\..").Path)

$backend = Join-Path $Root "backend"
$agent = Join-Path $Root "agent-windows"
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

Write-Output "Instalando tareas Windows tipo servicio para SOCSentinel..."

schtasks /Create /TN "SOCSentinel Backend" /SC ONLOGON /RL HIGHEST /F /TR "`"$ps`" -NoProfile -ExecutionPolicy Bypass -Command `"cd '$backend'; npm run dev`""
schtasks /Create /TN "SOCSentinel Agent" /SC ONLOGON /RL HIGHEST /F /TR "`"$ps`" -NoProfile -ExecutionPolicy Bypass -Command `"cd '$agent'; npm start`""

Write-Output "Listo. SOCSentinel Backend y Agent se iniciaran al iniciar sesion."

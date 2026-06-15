param([string]$Target)

if (-not $Target) {
  Write-Error "Debe indicar PID, nombre de proceso o ruta."
  exit 1
}

$protected = @("System","Registry","smss","csrss","wininit","winlogon","services","lsass","svchost","explorer","MsMpEng")
$matches = @()

if ($Target -match '^\d+$') {
  $matches = @(Get-Process -Id ([int]$Target) -ErrorAction SilentlyContinue)
} else {
  $name = [System.IO.Path]::GetFileNameWithoutExtension($Target)
  if ($name) {
    $matches = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
  }
}

if (-not $matches -or $matches.Count -eq 0) {
  Write-Error "No se encontro proceso para: $Target"
  exit 1
}

foreach ($proc in $matches) {
  if ($protected -contains $proc.ProcessName) {
    Write-Output "Omitido proceso protegido: $($proc.ProcessName) PID $($proc.Id)"
    continue
  }
  Stop-Process -Id $proc.Id -Force
  Write-Output "Proceso detenido: $($proc.ProcessName) PID $($proc.Id)"
}

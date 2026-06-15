param([Parameter(Mandatory=$true)][string]$Target)

if (!(Test-Path -LiteralPath $Target)) {
  Write-Error "Archivo no encontrado: $Target"
  exit 1
}

$root = Join-Path $env:ProgramData "SOCSentinel\Quarantine"
New-Item -ItemType Directory -Force -Path $root | Out-Null
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Target).Hash
$name = Split-Path -Leaf $Target
$dest = Join-Path $root "$hash-$name"
Move-Item -LiteralPath $Target -Destination $dest -Force
Write-Output "Archivo en cuarentena: $dest"

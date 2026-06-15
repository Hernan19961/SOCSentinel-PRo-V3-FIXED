param([string]$Target)
if (-not $Target) { Write-Error "IP requerida"; exit 1 }

$names = @(
  "SOCSentinel Block $Target",
  "SOCSentinel Block OUT $Target",
  "SOCSentinel Deep Block IN $Target",
  "SOCSentinel Deep Block OUT $Target",
  "SOCSentinel Deep Block Any IN $Target",
  "SOCSentinel Deep Block Any OUT $Target"
)

foreach ($name in $names) {
  Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
}

Write-Output "IP desbloqueada por SOCSentinel: $Target"

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

New-NetFirewallRule -DisplayName "SOCSentinel Deep Block IN $Target" `
  -Direction Inbound `
  -RemoteAddress $Target `
  -Action Block `
  -Profile Any `
  -Protocol TCP `
  -LocalPort Any `
  -RemotePort Any `
  -EdgeTraversalPolicy Block `
  -ErrorAction Stop | Out-Null

New-NetFirewallRule -DisplayName "SOCSentinel Deep Block OUT $Target" `
  -Direction Outbound `
  -RemoteAddress $Target `
  -Action Block `
  -Profile Any `
  -Protocol TCP `
  -LocalPort Any `
  -RemotePort Any `
  -ErrorAction Stop | Out-Null

New-NetFirewallRule -DisplayName "SOCSentinel Deep Block Any IN $Target" `
  -Direction Inbound `
  -RemoteAddress $Target `
  -Action Block `
  -Profile Any `
  -Protocol Any `
  -EdgeTraversalPolicy Block `
  -ErrorAction Stop | Out-Null

New-NetFirewallRule -DisplayName "SOCSentinel Deep Block Any OUT $Target" `
  -Direction Outbound `
  -RemoteAddress $Target `
  -Action Block `
  -Profile Any `
  -Protocol Any `
  -ErrorAction Stop | Out-Null

Write-Output "IP bloqueada profundamente por SOCSentinel: $Target"
Write-Output "Reglas inbound/outbound aplicadas a todos los perfiles y protocolos."

param([string]$Target)

if (-not $Target -or -not ($Target -match '^\d{1,5}$')) {
  Write-Error "Debe indicar un puerto TCP valido."
  exit 1
}

$Port = [int]$Target
if ($Port -lt 1 -or $Port -gt 65535) {
  Write-Error "Puerto fuera de rango."
  exit 1
}

$ruleName = "SOCSentinel Block Port $Port"
Get-NetFirewallRule -DisplayName "$ruleName*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

New-NetFirewallRule -DisplayName "$ruleName Inbound TCP" -Direction Inbound -Action Block -Protocol TCP -LocalPort $Port -Profile Any | Out-Null
New-NetFirewallRule -DisplayName "$ruleName Inbound UDP" -Direction Inbound -Action Block -Protocol UDP -LocalPort $Port -Profile Any | Out-Null

Write-Output "Puerto local $Port bloqueado en Windows Firewall (TCP/UDP inbound)."

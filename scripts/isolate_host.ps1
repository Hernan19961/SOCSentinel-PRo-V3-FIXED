param([string]$Target)
Write-Warning "Aislamiento local defensivo. Ejecutar solo en el equipo propio que quieres aislar. Target recibido: $Target"
New-NetFirewallRule -DisplayName "SOCSentinel Isolation Inbound" -Direction Inbound -Action Block -Profile Any -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "SOCSentinel Isolation Outbound" -Direction Outbound -Action Block -Profile Any -ErrorAction SilentlyContinue
Write-Output "Equipo aislado mediante firewall local. Para revertir: Remove-NetFirewallRule -DisplayName 'SOCSentinel Isolation*'"

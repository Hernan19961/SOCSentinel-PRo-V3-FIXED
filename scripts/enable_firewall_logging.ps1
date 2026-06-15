Write-Host "Enabling Windows Firewall logging for SOCSentinel..." -ForegroundColor Cyan

$logDir = "$env:SystemRoot\System32\LogFiles\Firewall"
$logFile = Join-Path $logDir "pfirewall.log"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed True -LogBlocked True -LogFileName $logFile -LogMaxSizeKilobytes 32767

try {
  auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"{0CCE9225-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
  Write-Output "Windows Filtering Platform auditing enabled."
} catch {
  Write-Warning "Could not enable auditpol Filtering Platform auditing: $($_.Exception.Message)"
}

Write-Output "Firewall logging enabled."
Write-Output "Log file: $logFile"
Write-Output "SOCSentinel agent will ingest recent entries from this file."

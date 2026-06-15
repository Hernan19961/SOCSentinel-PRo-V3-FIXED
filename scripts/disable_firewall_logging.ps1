Write-Host "Disabling Windows Firewall logging for SOCSentinel..." -ForegroundColor Cyan

Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed False -LogBlocked False

try {
  auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable | Out-Null
  auditpol /set /subcategory:"{0CCE9225-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable | Out-Null
  Write-Output "Windows Filtering Platform auditing disabled."
} catch {
  Write-Warning "Could not disable auditpol Filtering Platform auditing: $($_.Exception.Message)"
}

Write-Output "Firewall logging disabled."

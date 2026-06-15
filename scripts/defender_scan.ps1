param([string]$Target)

if (-not $Target -or $Target -eq "QuickScan") {
  Start-MpScan -ScanType QuickScan
  Write-Output "QuickScan real de Microsoft Defender iniciado."
  exit 0
}

if ($Target -eq "FullScan") {
  Start-MpScan -ScanType FullScan
  Write-Output "FullScan real de Microsoft Defender iniciado."
  exit 0
}

if (Test-Path -LiteralPath $Target) {
  Start-MpScan -ScanType CustomScan -ScanPath $Target
  Write-Output "Escaneo Defender real iniciado sobre: $Target"
} else {
  Start-MpScan -ScanType QuickScan
  Write-Output "El objetivo no es una ruta local existente. Se inicio QuickScan real de Microsoft Defender."
}

$ErrorActionPreference = "Stop"
$script:DefenderErrors = @()

function SafeRun($Name, $ScriptBlock, $Fallback) {
  try {
    & $ScriptBlock
  } catch {
    $script:DefenderErrors += "${Name}: $($_.Exception.Message)"
    $Fallback
  }
}

$status = SafeRun "Get-MpComputerStatus" { Get-MpComputerStatus } $null
$prefs = SafeRun "Get-MpPreference" { Get-MpPreference } $null
$detections = SafeRun "Get-MpThreatDetection" { Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 25 } @()
$threats = SafeRun "Get-MpThreat" { Get-MpThreat | Select-Object -First 50 } @()

$activeDetections = @($detections | Where-Object {
  $_.ActionSuccess -eq $false -or
  $_.ThreatStatusID -notin @(3, 4, 5) -or
  [string]$_.ThreatStatusID -eq ''
})

$payload = [ordered]@{
  ok = [bool]$status
  error = if ($status) { "" } else { ($script:DefenderErrors -join " | ") }
  generatedAt = (Get-Date).ToString("o")
  engine = if ($status) {
    [ordered]@{
      antivirusEnabled = [bool]$status.AntivirusEnabled
      realTimeProtectionEnabled = [bool]$status.RealTimeProtectionEnabled
      behaviorMonitorEnabled = [bool]$status.BehaviorMonitorEnabled
      antispywareEnabled = [bool]$status.AntispywareEnabled
      ioavProtectionEnabled = [bool]$status.IoavProtectionEnabled
      tamperProtection = [string]$status.IsTamperProtected
      quickScanAge = $status.QuickScanAge
      fullScanAge = $status.FullScanAge
      lastQuickScan = $status.QuickScanStartTime
      lastFullScan = $status.FullScanStartTime
      antivirusSignatureAge = $status.AntivirusSignatureAge
      antivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
      antivirusSignatureVersion = $status.AntivirusSignatureVersion
      nISEnabled = [bool]$status.NISEnabled
      nisSignatureAge = $status.NISSignatureAge
    }
  } else { $null }
  preferences = if ($prefs) {
    [ordered]@{
      disableRealtimeMonitoring = [bool]$prefs.DisableRealtimeMonitoring
      disableBehaviorMonitoring = [bool]$prefs.DisableBehaviorMonitoring
      disableIOAVProtection = [bool]$prefs.DisableIOAVProtection
      cloudBlockLevel = [string]$prefs.CloudBlockLevel
      cloudExtendedTimeout = $prefs.CloudExtendedTimeout
      submitSamplesConsent = [string]$prefs.SubmitSamplesConsent
      scanScheduleDay = [string]$prefs.ScanScheduleDay
      scanScheduleTime = [string]$prefs.ScanScheduleTime
      exclusionPath = @($prefs.ExclusionPath)
      exclusionProcess = @($prefs.ExclusionProcess)
      exclusionExtension = @($prefs.ExclusionExtension)
    }
  } else { $null }
  summary = [ordered]@{
    activeThreats = @($activeDetections).Count
    totalDetections = @($detections).Count
    knownThreats = @($threats).Count
    protectionHealthy = [bool]($status -and $status.AntivirusEnabled -and $status.RealTimeProtectionEnabled)
  }
  detections = @($detections | ForEach-Object {
    [ordered]@{
      threatId = $_.ThreatID
      threatName = $_.ThreatName
      severityId = $_.SeverityID
      categoryId = $_.CategoryID
      actionSuccess = $_.ActionSuccess
      resources = @($_.Resources)
      initialDetectionTime = $_.InitialDetectionTime
      lastThreatStatusChangeTime = $_.LastThreatStatusChangeTime
      threatStatusId = $_.ThreatStatusID
      processName = $_.ProcessName
      remediationTime = $_.RemediationTime
      domainUser = $_.DomainUser
    }
  })
  knownThreats = @($threats | ForEach-Object {
    [ordered]@{
      threatId = $_.ThreatID
      threatName = $_.ThreatName
      severityId = $_.SeverityID
      categoryId = $_.CategoryID
      defaultAction = $_.DefaultAction
      statusId = $_.StatusID
      resources = @($_.Resources)
    }
  })
}

$payload | ConvertTo-Json -Depth 8 -Compress

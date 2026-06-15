param(
  [Parameter(Mandatory=$true)][string]$Path,
  [string]$Api = "http://127.0.0.1:4000/api/events"
)

if (!(Test-Path -LiteralPath $Path)) {
  Write-Error "EVTX no encontrado: $Path"
  exit 1
}

$events = Get-WinEvent -Path $Path -MaxEvents 500 | Select-Object TimeCreated,Id,RecordId,ProviderName,MachineName,Message
$payload = @($events | ForEach-Object {
  [ordered]@{
    eventId = $_.Id
    provider = $_.ProviderName
    hostname = $_.MachineName
    recordId = $_.RecordId
    timestamp = $_.TimeCreated
    rawMessage = $_.Message
    commandLine = $_.Message
    raw = $_
  }
})

Invoke-RestMethod -Uri $Api -Method Post -ContentType "application/json" -Body ($payload | ConvertTo-Json -Depth 5)
Write-Output "EVTX importado: $($payload.Count) eventos enviados a SOCSentinel."

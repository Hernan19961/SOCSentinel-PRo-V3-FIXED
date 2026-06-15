$ErrorActionPreference = "Stop"

$ServiceName = "postgresql-x64-16"
$DataDir = "C:\Program Files\PostgreSQL\16\data"
$Psql = "C:\Program Files\PostgreSQL\16\bin\psql.exe"
$PgHba = Join-Path $DataDir "pg_hba.conf"
$Backup = Join-Path $DataDir ("pg_hba.conf.socsentinel-backup-" + (Get-Date -Format "yyyyMMddHHmmss"))
$NewPassword = "Hernanxd"

Write-Host "SOCSentinel PostgreSQL repair" -ForegroundColor Cyan
Write-Host "Backing up pg_hba.conf..." -ForegroundColor Yellow
Copy-Item -LiteralPath $PgHba -Destination $Backup -Force

try {
  $content = Get-Content -LiteralPath $PgHba
  $patched = foreach ($line in $content) {
    if ($line -match "^\s*host\s+all\s+all\s+127\.0\.0\.1/32\s+scram-sha-256") {
      "host    all             all             127.0.0.1/32            trust"
    } elseif ($line -match "^\s*host\s+all\s+all\s+::1/128\s+scram-sha-256") {
      "host    all             all             ::1/128                 trust"
    } else {
      $line
    }
  }
  Set-Content -LiteralPath $PgHba -Value $patched

  Write-Host "Restarting PostgreSQL with temporary local trust..." -ForegroundColor Yellow
  Restart-Service -Name $ServiceName -Force
  Start-Sleep -Seconds 4

  Write-Host "Setting postgres password and ensuring database exists..." -ForegroundColor Yellow
  & $Psql -U postgres -h 127.0.0.1 -d postgres -c "ALTER USER postgres WITH PASSWORD '$NewPassword';"
  $databaseExists = & $Psql -U postgres -h 127.0.0.1 -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='socsentinel';"
  if ($databaseExists -ne "1") {
    & $Psql -U postgres -h 127.0.0.1 -d postgres -c "CREATE DATABASE socsentinel;"
  }
} finally {
  Write-Host "Restoring pg_hba.conf and restarting PostgreSQL..." -ForegroundColor Yellow
  Copy-Item -LiteralPath $Backup -Destination $PgHba -Force
  Restart-Service -Name $ServiceName -Force
  Start-Sleep -Seconds 4
}

$env:PGPASSWORD = $NewPassword
& $Psql -U postgres -h 127.0.0.1 -d socsentinel -c "SELECT current_database(), current_user;"
Write-Host "PostgreSQL password reset complete for SOCSentinel." -ForegroundColor Green

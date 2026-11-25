# Task-Ayuza on this Windows computer with a public HTTPS link (Tailscale Funnel).
# Requirements: Docker Desktop running; a Tailscale account with MagicDNS, HTTPS certificates
# and Funnel enabled (see deploy/README.md). Safe to run again: secrets are generated once
# into deploy/.env (never committed), data stays in Docker volumes.
# Usage (PowerShell, from the repository folder):  powershell -ExecutionPolicy Bypass -File deploy\setup.ps1
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 on older .NET does not offer TLS 1.2 by default; ts.net requires it.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Set-Location $PSScriptRoot
$compose = @('compose', '--env-file', '.env', '-f', 'docker-compose.yml')

function New-Secret([int]$bytes) {
    $buffer = New-Object byte[] $bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    -join ($buffer | ForEach-Object { $_.ToString('x2') })
}

function Set-EnvValue([string]$name, [string]$value) {
    $lines = Get-Content .env | Where-Object { $_ -notmatch "^$name=" }
    ($lines + "$name=$value") | Set-Content -Encoding ascii .env
}

function Invoke-Docker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "docker $($args -join ' ') failed with exit code $LASTEXITCODE" }
}

# Windows PowerShell 5.1 turns redirected stderr of a native command into a terminating error
# when ErrorActionPreference is Stop, so probes that may fail run with Continue.
function Invoke-Probe {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & docker @args 2>$null
        [pscustomobject]@{ Code = $LASTEXITCODE; Output = ($output | Out-String) }
    } finally { $ErrorActionPreference = $previous }
}

if ((Invoke-Probe version --format '{{.Server.Version}}').Code -ne 0) {
    throw 'Docker Desktop is not running. Start it and run this script again.'
}

if (-not (Test-Path .env)) {
    Write-Host 'First run: generating secrets into deploy\.env'
    $secure = Read-Host 'Paste the Tailscale auth key (starts with tskey-auth-)' -AsSecureString
    $authKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    if ($authKey -notmatch '^tskey-auth-[A-Za-z0-9-]+$') { throw 'That does not look like a Tailscale auth key.' }
    @(
        "TA_ADMIN_PASSWORD=$(New-Secret 24)",
        "TA_MIGRATOR_PW=$(New-Secret 24)",
        "TA_RUNTIME_PW=$(New-Secret 24)",
        "TA_BACKUP_PW=$(New-Secret 24)",
        "TA_HMAC_KEY=$(New-Secret 32)",
        "TA_MFA_KEY=$(New-Secret 32)",
        "TS_AUTHKEY=$authKey",
        "TA_HOSTNAME=pending.invalid"
    ) | Set-Content -Encoding ascii .env
    # Only the current user may read the secrets file.
    icacls .env /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):(R,W)" > $null
}

Write-Host 'Starting database, migrations and Tailscale...'
Invoke-Docker @compose up -d --build db init tailscale

$name = $null
for ($i = 0; $i -lt 60 -and -not $name; $i++) {
    Start-Sleep -Seconds 2
    $probe = Invoke-Probe @compose exec -T tailscale tailscale status --json
    if ($probe.Code -eq 0 -and $probe.Output.Trim()) {
        try { $status = $probe.Output | ConvertFrom-Json } catch { continue }
        if ($status.BackendState -eq 'Running' -and $status.Self.DNSName) { $name = $status.Self.DNSName.TrimEnd('.') }
    }
}
if (-not $name) {
    throw 'Tailscale did not come up. Check the auth key and: docker compose -f deploy\docker-compose.yml logs tailscale'
}
Set-EnvValue 'TA_HOSTNAME' $name

Write-Host "Starting the application for https://$name ..."
Invoke-Docker @compose up -d --build backend

# The first certificate can take a minute; the link answers once Funnel is active.
$ok = $false
for ($i = 0; $i -lt 45 -and -not $ok; $i++) {
    Start-Sleep -Seconds 4
    try {
        $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 "https://$name/openapi.json"
        $ok = $r.StatusCode -eq 200
    } catch { }
}

# Backups: one age key pair; the public half encrypts every copy, the private half
# (deploy\backup-keys\backup-identity.txt) is needed only to restore.
New-Item -ItemType Directory -Force backups, backup-keys | Out-Null
if (-not (Test-Path backup-keys\backup-identity.txt)) {
    Write-Host 'Creating the backup encryption key...'
    Invoke-Docker @compose run --rm --no-deps backup age-keygen -o /keys/backup-identity.txt
    icacls backup-keys /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):(OI)(CI)F" > $null
}
$recipient = (& docker @compose run --rm --no-deps backup age-keygen -y /keys/backup-identity.txt | Out-String).Trim()
if ($recipient -notmatch '^age1[0-9a-z]{58}$') { throw 'Could not read the backup public key.' }
Set-EnvValue 'TA_BACKUP_RECIPIENT' $recipient
# Asked again while empty, so a skipped answer can be filled in by re-running setup.
if (-not (Select-String -Path .env -Pattern '^TA_BACKUP_COPY_TO=.+' -Quiet)) {
    $target = Read-Host 'Tailscale name of the work computer for a second backup copy (empty to skip)'
    if ($target -and $target -notmatch '^[A-Za-z0-9-]+$') { throw 'Use the short Tailscale machine name, e.g. work-pc.' }
    Set-EnvValue 'TA_BACKUP_COPY_TO' $target
}
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSScriptRoot\backup.ps1`""
$trigger = New-ScheduledTaskTrigger -Daily -At 13:00
$taskSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName 'Task-Ayuza backup' -Action $action -Trigger $trigger -Settings $taskSettings -Force | Out-Null
# Restart: Docker Desktop starts only after sign-in, then start.ps1 brings the stack up and logs to
# deploy\backups\start.log. Automatic sign-in after a restart is a manual step (deploy/README.md).
$startAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSScriptRoot\start.ps1`""
$startTrigger = New-ScheduledTaskTrigger -AtLogOn -User "$($env:USERDOMAIN)\$($env:USERNAME)"
$startSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'Task-Ayuza start' -Action $startAction -Trigger $startTrigger -Settings $startSettings -Force | Out-Null
Write-Host 'Start after sign-in scheduled (task "Task-Ayuza start").'
Write-Host 'Daily backup scheduled (13:00, or as soon as the computer is on). First backup and restore check now...'
& powershell -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\backup.ps1" -RestoreCheck
if ($LASTEXITCODE -ne 0) { Write-Host 'Backup or restore check FAILED, see deploy\backups\backup.log' -ForegroundColor Red }

Write-Host ''
if ($ok) {
    Write-Host "Task-Ayuza is up:  https://$name/app/" -ForegroundColor Green
} else {
    Write-Host "Started, but https://$name/ does not answer yet." -ForegroundColor Yellow
    Write-Host 'Check that Funnel and HTTPS certificates are enabled for the tailnet (deploy/README.md), then:'
    Write-Host '  docker compose -f deploy\docker-compose.yml logs tailscale backend'
}
Write-Host 'The computer must stay on and awake for others to use the link.'
Write-Host 'Stop:  docker compose -f deploy\docker-compose.yml --env-file deploy\.env stop   (data is kept)'

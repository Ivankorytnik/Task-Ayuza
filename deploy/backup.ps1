# Daily encrypted backup of Task-Ayuza (run by Task Scheduler; see setup.ps1).
# 1. Encrypted dump into deploy\backups (kept 30 days).
# 2. Optional copy to the work computer over Tailscale (TA_BACKUP_COPY_TO in deploy\.env).
# 3. On Mondays, or with -RestoreCheck: restore the newest copy into a throwaway database
#    and compare it with the live one.
# Every step is logged to deploy\backups\backup.log. Exit code is non-zero on any failure.
param([switch]$RestoreCheck)
# Native commands write progress to stderr; failures are detected by exit codes instead.
$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot
$compose = @('compose', '--env-file', '.env', '-f', 'docker-compose.yml')
New-Item -ItemType Directory -Force backups | Out-Null
$log = Join-Path $PSScriptRoot 'backups\backup.log'

function Write-Log([string]$message) {
    $line = "$(Get-Date -Format 's') $message"
    Add-Content -Encoding ascii -Path $log -Value $line
    Write-Host $line
}

function Invoke-Step([string]$label) {
    # In Windows PowerShell 5.1 stderr lines arrive as ErrorRecords; "$_" gives their plain text.
    $output = @(& docker @compose @args 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    foreach ($line in ($output | Where-Object { $_ -match '^(backup|restore-check|pg_dump|pg_restore|age|psql):' })) {
        Write-Log "  $line"
    }
    if ($code -ne 0) { Write-Log "FAIL $label (exit $code)"; return $false }
    Write-Log "OK   $label"
    return $true
}

$settings = @{}
Get-Content .env | Where-Object { $_ -match '^[A-Z0-9_]+=' } | ForEach-Object {
    $name, $value = $_ -split '=', 2
    $settings[$name] = $value
}
if (-not $settings['TA_BACKUP_RECIPIENT']) { Write-Log 'FAIL no backup key configured; run setup.ps1'; exit 1 }

$failed = $false
if (-not (Invoke-Step 'encrypted backup' run --rm backup backup.sh)) { $failed = $true }

$target = $settings['TA_BACKUP_COPY_TO']
if (-not $failed -and -not $target) {
    Write-Log 'SKIP copy to work computer: TA_BACKUP_COPY_TO is empty in deploy\.env'
} elseif (-not $failed) {
    # Taildrop only sends to online devices of the same Tailscale account; check first for a clear log line.
    $targets = @(& docker @compose exec -T tailscale tailscale file cp --targets 2>&1 | ForEach-Object { "$_" })
    if (-not ($targets | Where-Object { ($_ -split '\s+') -contains $target })) {
        Write-Log "FAIL copy: '$target' is not a Taildrop target (not in this tailnet, offline or another account)"
        $failed = $true
    } else {
        $latest = Get-ChildItem -Path backups -Filter 'task-ayuza-*.dump.age' |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not (Invoke-Step "copy $($latest.Name) to $target" exec -T tailscale tailscale file cp "/backups/$($latest.Name)" "${target}:")) {
            $failed = $true
        }
    }
}

if (-not $failed -and ($RestoreCheck -or (Get-Date).DayOfWeek -eq 'Monday')) {
    if (-not (Invoke-Step 'restore check' run --rm backup restore-check.sh)) { $failed = $true }
}

if ($failed) { exit 1 }
exit 0

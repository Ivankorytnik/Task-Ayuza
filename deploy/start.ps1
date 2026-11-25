# Start Task-Ayuza after Windows signs in (Task Scheduler task "Task-Ayuza start", see setup.ps1).
# Docker Desktop starts only after a user signs in; this script waits for it (up to 10 minutes),
# then brings the stack up and checks the public link. Data is never changed here.
# Every run is logged to deploy\backups\start.log.
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Set-Location $PSScriptRoot
$compose = @('compose', '--env-file', '.env', '-f', 'docker-compose.yml')
New-Item -ItemType Directory -Force backups | Out-Null
$log = Join-Path $PSScriptRoot 'backups\start.log'

function Write-Log([string]$message) {
    Add-Content -Encoding ascii -Path $log -Value "$(Get-Date -Format 's') $message"
}

if (-not (Test-Path .env)) { Write-Log 'FAIL no deploy\.env; run setup.ps1 first'; exit 1 }

# With automatic sign-in (deploy/README.md, "after a restart") nobody is at the screen:
# lock it at once. Docker Desktop and the containers keep running while the screen is locked.
$winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($winlogon -and "$($winlogon.AutoAdminLogon)" -eq '1') {
    & rundll32.exe user32.dll,LockWorkStation
    Write-Log 'OK   automatic sign-in detected, screen locked'
}

# Docker Desktop may be slow to start right after sign-in; start it if it is not running yet.
$desktop = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
$ready = $false
for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
    & docker version --format '{{.Server.Version}}' 2>$null | Out-Null
    $ready = $LASTEXITCODE -eq 0
    if (-not $ready) {
        if ($i -eq 3 -and (Test-Path $desktop) -and -not (Get-Process 'Docker Desktop' -ErrorAction SilentlyContinue)) {
            Start-Process $desktop
        }
        Start-Sleep -Seconds 10
    }
}
if (-not $ready) { Write-Log 'FAIL Docker Desktop did not start within 10 minutes'; exit 1 }

# Same services as setup.ps1, without rebuilding images; init runs migrations again (idempotent).
& docker @compose up -d db init tailscale backend 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Log "FAIL docker compose up (exit $LASTEXITCODE)"; exit 1 }

$name = (Get-Content .env | Where-Object { $_ -match '^TA_HOSTNAME=' }) -replace '^TA_HOSTNAME=', ''
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 10
    try {
        $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 "https://$name/openapi.json"
        if ($r.StatusCode -eq 200) { Write-Log "OK   https://$name/app/ answers"; exit 0 }
    } catch { }
}
Write-Log "FAIL https://$name/ does not answer after 5 minutes"
exit 1

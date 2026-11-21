# Local start of Task-Ayuza (Docker Desktop required). Generates secrets once into .env.local (not in Git).
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
function New-Hex($bytes) { -join ((1..$bytes) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) }) }
if (-not (Test-Path .env.local)) {
    @(
        "TA_ADMIN_PASSWORD=$(New-Hex 16)", "TA_MIGRATOR_PW=$(New-Hex 16)",
        "TA_RUNTIME_PW=$(New-Hex 16)", "TA_BACKUP_PW=$(New-Hex 16)", "TA_HMAC_KEY=$(New-Hex 32)"
    ) | Set-Content -Encoding ascii .env.local
}
docker compose --env-file .env.local up -d --build
Write-Host "Demo:    https://localhost:8443/demo/   (accept the local certificate warning once)"
Write-Host "Backend: https://localhost:8443/openapi.json"
Write-Host "Stop:    docker compose down   (data kept; add -v to wipe)"

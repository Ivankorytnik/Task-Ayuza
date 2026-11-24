# Operator commands for Task-Ayuza on this computer (see deploy/README.md).
# Examples:  deploy\admin.ps1 status
#            deploy\admin.ps1 create-user ivan "Ivan Petrov"
#            deploy\admin.ps1 session ivan
# Passwords and MFA codes are typed at the prompt, never on the command line.
Set-Location $PSScriptRoot
& docker compose --env-file .env -f docker-compose.yml run --rm --build admin @args
exit $LASTEXITCODE

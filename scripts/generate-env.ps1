# Windows equivalent of generate-env.sh: creates .env from .env.example with
# freshly generated random secrets.
#
#   powershell -ExecutionPolicy Bypass -File scripts\generate-env.ps1 [-Force]
#
# Works with Windows PowerShell 5.1 and PowerShell 7+.
param([switch]$Force)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$example = Join-Path $root '.env.example'
$target = Join-Path $root '.env'

if ((Test-Path $target) -and -not $Force) {
    Write-Host '.env already exists (use -Force to overwrite)'
    exit 1
}

$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

function New-Secret([int]$length) {
    $bytes = New-Object byte[] $length
    $rng.GetBytes($bytes)
    $chars = foreach ($b in $bytes) { $alphabet[$b % $alphabet.Length] }
    return -join $chars
}

$lengths = @{
    'POSTGRES_PASSWORD'   = 32
    'JWT_SECRET'          = 64
    'DEMO_ALICE_PASSWORD' = 16
    'DEMO_BOB_PASSWORD'   = 16
    'DEMO_ADMIN_PASSWORD' = 16
    'TRACKER_API_KEY'     = 40
    'ANALYST1_PASSWORD'   = 16
    'SOC_LEAD_PASSWORD'   = 16
}

$lines = foreach ($line in [System.IO.File]::ReadAllLines($example)) {
    $key = ($line -split '=', 2)[0]
    if ($lengths.ContainsKey($key)) { "$key=$(New-Secret $lengths[$key])" } else { $line }
}

# UTF-8 without BOM and LF line endings, so docker compose parses it cleanly.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($target, (($lines -join "`n") + "`n"), $utf8NoBom)

Write-Host 'Wrote .env with random secrets. Analyst logins:'
Get-Content $target | Where-Object { $_ -match '^(ANALYST1|SOC_LEAD)_PASSWORD=' }

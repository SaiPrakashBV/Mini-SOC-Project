#!/bin/sh
# One-shot initialisation for OpenSearch: index templates, retention policy and an
# example native Alerting monitor. Idempotent - safe to run on every `compose up`.
set -eu

OS_URL="${OPENSEARCH_URL:-http://opensearch:9200}"
DIR="$(dirname "$0")"

echo "Waiting for OpenSearch at ${OS_URL} ..."
until curl -fsS "${OS_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" >/dev/null 2>&1; do
  sleep 3
done

put() {
  # $1 = path, $2 = file
  code=$(curl -sS -o /tmp/resp.json -w '%{http_code}' -X PUT "${OS_URL}$1" \
    -H 'Content-Type: application/json' --data-binary "@$2")
  echo "PUT $1 -> ${code}"
  case "$code" in 2*) ;; *) cat /tmp/resp.json; echo ;; esac
}

put "/_index_template/security-events" "${DIR}/templates/security-events.json"
put "/_index_template/soc-alerts"      "${DIR}/templates/soc-alerts.json"

# Create the alert index up-front so the dashboard works before the first alert.
curl -sS -o /dev/null -X PUT "${OS_URL}/soc-alerts" -H 'Content-Type: application/json' -d '{}' || true

# ISM policy (PUT fails with 409 if it already exists - that's fine).
put "/_plugins/_ism/policies/security-events-retention" "${DIR}/ism-retention-policy.json" || true

# Optional: OpenSearch's built-in Alerting plugin as a second detection layer.
# Only created once (looked up by name).
existing=$(curl -sS -X GET "${OS_URL}/_plugins/_alerting/monitors/_search" -H 'Content-Type: application/json' \
  -d '{"query":{"match_phrase":{"monitor.name":"Native monitor - brute-force logins"}}}' 2>/dev/null || echo '')
case "$existing" in
  *'"total":{"value":0'*|'')
    curl -sS -o /dev/null -w 'POST monitor -> %{http_code}\n' -X POST "${OS_URL}/_plugins/_alerting/monitors" \
      -H 'Content-Type: application/json' --data-binary "@${DIR}/monitors/brute-force-monitor.json" || true ;;
  *) echo "Monitor already present" ;;
esac

echo "OpenSearch initialisation complete."

#!/usr/bin/env bash
# Creates .env from .env.example with freshly generated random secrets.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env && "${1:-}" != "--force" ]]; then
  echo ".env already exists (use --force to overwrite)"; exit 1
fi

rand() { openssl rand -base64 "$1" | tr -d '/+=\n' | cut -c1-"$2"; }

sed \
  -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(rand 32 32)|" \
  -e "s|^JWT_SECRET=.*|JWT_SECRET=$(rand 64 64)|" \
  -e "s|^DEMO_ALICE_PASSWORD=.*|DEMO_ALICE_PASSWORD=$(rand 18 16)|" \
  -e "s|^DEMO_BOB_PASSWORD=.*|DEMO_BOB_PASSWORD=$(rand 18 16)|" \
  -e "s|^DEMO_ADMIN_PASSWORD=.*|DEMO_ADMIN_PASSWORD=$(rand 18 16)|" \
  -e "s|^TRACKER_API_KEY=.*|TRACKER_API_KEY=$(rand 48 40)|" \
  -e "s|^ANALYST1_PASSWORD=.*|ANALYST1_PASSWORD=$(rand 18 16)|" \
  -e "s|^SOC_LEAD_PASSWORD=.*|SOC_LEAD_PASSWORD=$(rand 18 16)|" \
  .env.example > .env
chmod 600 .env
echo "Wrote .env with random secrets. Analyst logins:"
grep -E '^(ANALYST1|SOC_LEAD)_PASSWORD' .env

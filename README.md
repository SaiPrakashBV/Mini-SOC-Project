# Mini SOC — Security Operations Center lab

A miniature SIEM/SOC built with Spring Boot, OpenSearch, Fluent Bit, PostgreSQL and React.
A target web application emits structured security events. They are shipped to OpenSearch,
and a detection engine runs threshold rules over them. Detections open incidents that
analysts triage from a dashboard.

```
 attacker / users
        │  HTTP (JWT)
        ▼
 ┌──────────────┐  JSON logs   ┌────────────┐   bulk    ┌────────────┐
 │  target-app  │ ───────────► │ fluent-bit │ ────────► │ OpenSearch │◄──── OpenSearch Dashboards
 │ Spring Boot  │ (shared vol) └────────────┘           │  security- │      (optional, --profile tools)
 └──────────────┘                                       │  events-*  │
                                                        └─────┬──────┘
                                         aggregation queries  │  ▲ soc-alerts
                                                              ▼  │
                                                    ┌───────────────────┐
                                                    │ detection-service │
                                                    │  threshold rules  │
                                                    └─────────┬─────────┘
                                          POST /api/incidents │ X-API-Key
                                                              ▼
 ┌──────────────┐  /tracker/*   ┌──────────────────┐   JPA   ┌────────────┐
 │   frontend   │ ────────────► │ incident-tracker │ ──────► │ PostgreSQL │
 │ React + nginx│ /detection/*  └──────────────────┘ Flyway  └────────────┘
 └──────────────┘ ────────────► detection-service
```

**Full documentation:** [`docs/Mini-SOC-Documentation.pdf`](docs/Mini-SOC-Documentation.pdf) (49 pages): architecture
diagrams, every file explained, data model, deployment, security controls, attack simulation, testing and troubleshooting.

**Presentations:** [`docs/Mini-SOC-Technical-Presentation.pptx`](docs/Mini-SOC-Technical-Presentation.pptx) (21 slides,
about 30 min, technical audience) and [`docs/Mini-SOC-Presentation.pptx`](docs/Mini-SOC-Presentation.pptx) (16 slides,
about 15 min, mixed audience), both with speaker notes.

## Repository layout

| Path | What it is |
|---|---|
| `target-app/` | Monitored app: `/api/auth/login`, `/api/users`, `/api/orders`, `/api/admin`. JWT auth, role-based access, structured JSON audit logs with correlation IDs |
| `incident-tracker/` | Incident REST API: create, filter, assign, status workflow, notes, audit history, stats. PostgreSQL + Flyway |
| `detection-service/` | Detection engine. Rules declared in YAML become OpenSearch aggregation queries. Alerts are stored in `soc-alerts` and forwarded to the tracker. Also serves the event and alert APIs for the dashboard |
| `frontend/` | React SOC dashboard: overview, incidents, alerts & rules, event explorer |
| `fluent-bit/` | Tails the target app's log file and ships to OpenSearch (`security-events-YYYY.MM.DD`) |
| `opensearch/` | Index templates, 14-day retention (ISM) policy, an example native Alerting monitor, and an init script |
| `database/` | PostgreSQL first-run initialization (read-only reporting role) |
| `scripts/` | `generate-env.sh` / `.ps1` (random secrets), `simulate-attacks.sh` / `.ps1` (all-in-one attack scenarios) |
| `attack-simulators/` | Six standalone Python attack campaigns (run locally or via `docker compose run --rm attacker …`) |
| `docker-compose.yml` | The whole stack |

## Quick start

Requirements: Docker with Compose v2 and about 4 GB of free RAM. OpenSearch needs
`vm.max_map_count >= 262144` on Linux hosts (`sudo sysctl -w vm.max_map_count=262144`).

```bash
./scripts/generate-env.sh          # creates .env with random secrets (git-ignored)
```

```bash
docker compose up -d --build
```

```bash
docker compose ps                  # wait until everything is healthy (~1-2 min)
```

```bash
./scripts/simulate-attacks.sh      # generate benign traffic + attacks
```

Open **http://localhost:3000** and sign in as `analyst1` or `lead`, with the password from `.env`.
Within about 20 seconds incidents appear. Click **Run detection now** on *Alerts & Rules* to skip the polling wait.

Optional OpenSearch Dashboards (to search raw events):

```bash
docker compose --profile tools up -d opensearch-dashboards   # http://localhost:5601
```

Without `generate-env.sh`, copy `.env.example` to `.env` and replace every `change-me` value.

### Windows

Use Docker Desktop (WSL 2 backend) and the PowerShell versions of the scripts. They work from
Command Prompt or PowerShell:

```bat
powershell -ExecutionPolicy Bypass -File scripts\generate-env.ps1
```

```bat
docker compose up -d --build
```

```bat
powershell -ExecutionPolicy Bypass -File scripts\simulate-attacks.ps1
```

Run one scenario with `... simulate-attacks.ps1 bruteforce`, or a group with `... simulate-attacks.ps1 advanced`. The `.gitattributes` file keeps shell
scripts and configs mounted into Linux containers on LF line endings. If you cloned before it existed,
refresh your working copy once:

```bat
git rm -r --cached -q . && git reset --hard
```

## Example workflow: brute force → incident → resolution

1. `./scripts/simulate-attacks.sh bruteforce` sends 6 wrong passwords for `alice` from `203.0.113.66`.
2. target-app logs each failure as a `LOGIN_FAILURE` event with timestamp, `source_ip`, `username` and `correlation_id`.
3. Fluent Bit ships the events to `security-events-*`.
4. `BRUTE_FORCE_LOGIN` (≥ 5 failures for one username in 2 min) fires. The alert is stored in `soc-alerts`, and a **HIGH** incident is created through `POST /api/incidents`.
5. The analyst opens the incident, assigns it, moves it to *Investigating*, reviews the evidence samples and the user's event timeline, adds notes, and resolves it. A resolution summary is required to resolve. Every change is written to the audit history.

If the attack continues after the rule's suppression window, the **same** open incident is
re-triggered (matched by fingerprint `rule:field:entity`). Its detection count goes up and
the severity can escalate. No duplicate incident is opened.

## Detection rules

Rules live in `detection-service/src/main/resources/application.yml`. You can add one without writing code.

| Rule | Logic | Severity |
|---|---|---|
| `BRUTE_FORCE_LOGIN` | ≥ 5 `LOGIN_FAILURE` per **username** in 2m | HIGH → CRITICAL at 20 |
| `PASSWORD_SPRAY` | ≥ 10 `LOGIN_FAILURE` per **source IP** in 5m | HIGH |
| `AUTH_ERROR_SPIKE` | ≥ 15 HTTP 401/403 per source IP in 5m | MEDIUM → HIGH at 60 |
| `HIGH_REQUEST_RATE` | ≥ 100 requests per source IP in 1m | MEDIUM → HIGH at 500 |
| `RESTRICTED_ENDPOINT_ACCESS` | ≥ 3 `ACCESS_DENIED` on `/api/admin*` per username in 5m | HIGH |
| `IDOR_ATTEMPT` | ≥ 3 `RESOURCE_OWNERSHIP_VIOLATION` per username in 10m | HIGH |
| `INVALID_TOKEN_ABUSE` | ≥ 10 `TOKEN_INVALID` per source IP in 5m | MEDIUM |
| `ACCOUNT_TAKEOVER` | ≥ 5 `LOGIN_FAILURE` **and** ≥ 1 `LOGIN_SUCCESS` from one source IP in 10m | CRITICAL |
| `DISTRIBUTED_BRUTE_FORCE` | ≥ 5 `LOGIN_FAILURE` per username from **≥ 5 distinct IPs** in 10m | HIGH |
| `SESSION_HIJACK` | one JWT (`token_id`) used successfully from **≥ 3 distinct IPs** in 10m | HIGH |
| `INJECTION_ATTEMPT` | ≥ 3 SQLi / XSS / path-traversal / command-injection payloads per IP in 5m | HIGH → CRITICAL at 20 |
| `LOG4SHELL_EXPLOIT` | any `${jndi:...}` lookup string (CVE-2021-44228) | CRITICAL |
| `SCANNER_TOOL` | ≥ 5 requests with a scanner user agent (sqlmap, nikto, nuclei…) per IP in 5m | MEDIUM |
| `RECON_PATH_SCAN` | 401/403/404 on **≥ 10 distinct paths** per IP in 2m | MEDIUM |
| `DATA_SCRAPING` | ≥ 40 successful `GET /api/orders*` per user in 1m | HIGH |
| `JWT_ALG_NONE` | any unsigned (`alg: none`) JWT | HIGH |

Rules support three kinds of condition, all configured in YAML:

- **Threshold:** `match` + `group-by` + `threshold` within `window`.
- **Cardinality:** `distinct-field` + `min-distinct`, e.g. many different IPs for one account.
- **Correlation:** `require`. The group must also contain a different kind of event, and the
  threshold counts only the `match` events (e.g. failures, then a success).

The injection, Log4Shell and scanner rules rely on `AttackSignatureFilter` in the target app. It is a
minimal WAF that inspects the path, query parameters and headers (not request bodies), logs a
`MALICIOUS_REQUEST` event with `attack_type`, and blocks payloads with HTTP 400. Scanner user agents
are logged but not blocked.

### Attack simulators

[`attack-simulators/`](attack-simulators/README.md) contains six standalone attack campaigns:
credential-stuffing botnet, vulnerability scanner, malicious insider, session hijack, Log4Shell
campaign and layer-7 DDoS. Run each one on its own and watch its detections appear in the dashboard:

```bash
docker compose run --rm attacker 1_credential_stuffing.py
```

```bash
python attack-simulators/2_vulnerability_scanner.py
```

The original all-in-one script is still available. Run one scenario, several, or the groups
`basic` / `advanced`; no argument runs all:

| Group | Scenarios |
|---|---|
| basic | `baseline bruteforce spray privesc idor tokens flood` |
| advanced | `takeover distributed hijack injection log4shell recon scanner scraping algnone` |

```bash
./scripts/simulate-attacks.sh advanced
```

```bash
./scripts/simulate-attacks.sh takeover hijack
```

## Security event schema (target-app)

Every line in `app.json` is one JSON object. Audit events carry these fields:

| Field | Example |
|---|---|
| `@timestamp` | `2026-10-30T20:05:25.724Z` (UTC) |
| `event_type` | `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `TOKEN_INVALID`, `UNAUTHORIZED`, `ACCESS_DENIED`, `RESOURCE_OWNERSHIP_VIOLATION`, `MALICIOUS_REQUEST`, `ADMIN_ACTION`, `ORDER_CREATED`, `HTTP_REQUEST` |
| `event_category` / `outcome` | `authentication` / `FAILURE` |
| `username`, `source_ip`, `correlation_id` | `alice`, `203.0.113.66`, UUID (also returned as the `X-Correlation-ID` header) |
| `http_method`, `http_path`, `http_status`, `duration_ms`, `user_agent` | on `HTTP_REQUEST` events |
| `token_id` | JWT id (`jti`) on every authenticated request |
| `attack_type`, `attack_location`, `attack_sample` | on `MALICIOUS_REQUEST`: e.g. `sql_injection`, `param:id`, the payload |
| `reason`, `roles`, `resource_id`, … | event-specific details |

## APIs

### Incident tracker (`/tracker` behind the dashboard, port 8081 inside the network)

| Method | Endpoint | Function |
|---|---|---|
| POST | `/api/incidents` | Create an incident. If an active incident has the same `fingerprint`, it is re-triggered instead (200 + `X-Incident-Deduplicated: true`) |
| GET | `/api/incidents` | List and filter: `status`, `severity` (repeatable), `assignee` (`unassigned`), `affectedUser`, `sourceIp`, `ruleId`, `q`, `from`, `to`, `page`, `size`, `sort`, `direction` |
| GET | `/api/incidents/{id}` | Details, including evidence, notes, history and allowed transitions |
| PATCH | `/api/incidents/{id}/status` | `{status, resolution?, comment?}`. Transitions are validated (409 when invalid) |
| PATCH | `/api/incidents/{id}/assign` | `{assignee}` (null to unassign) |
| PATCH | `/api/incidents/{id}/severity` | `{severity}` |
| POST | `/api/incidents/{id}/notes` | `{content}` |
| GET | `/api/incidents/stats` | Counts by status and severity, unassigned, MTTA/MTTR, top users/IPs/rules |
| GET | `/api/analysts`, `/api/me` | Analyst directory and the current user |

Status flow: `OPEN → INVESTIGATING → CONTAINED → RESOLVED → CLOSED`. `FALSE_POSITIVE` can be
reached from OPEN or INVESTIGATING. RESOLVED, FALSE_POSITIVE and CLOSED can be re-opened to INVESTIGATING.

Auth: analysts use HTTP Basic (role ANALYST). The detection service uses `X-API-Key` (role SERVICE),
which can only create and read incidents.

### Detection service (`/detection`, port 8082)

`GET /api/alerts`, `GET /api/alerts/summary`, `GET /api/rules`, `POST /api/rules/run`,
`GET /api/events/recent`, `GET /api/events/timeline?username=|sourceIp=|correlationId=`,
`GET /api/events/activity`, `GET /api/health/pipeline`.

### Target app (port 8080)

```bash
TOKEN=$(curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"<DEMO_ALICE_PASSWORD>"}' | jq -r .accessToken)
```

```bash
curl -H "Authorization: Bearer $TOKEN" localhost:8080/api/orders
```

## Local development without Docker

Each Spring service runs with `mvn spring-boot:run` once its environment variables are exported.
Run the frontend with `cd frontend && npm install && npm run dev`. The Vite dev server proxies
`/tracker` and `/detection` to ports 8081 and 8082.

```bash
cd target-app && mvn test          # same for incident-tracker and detection-service
```

## Hardening notes (this is a lab)

- OpenSearch runs **with its security plugin disabled** and is bound to `127.0.0.1`. For anything
  shared, enable the plugin, set `OPENSEARCH_INITIAL_ADMIN_PASSWORD`, switch Fluent Bit to
  `tls On` with `HTTP_User`/`HTTP_Passwd`, and set `OPENSEARCH_USER`/`OPENSEARCH_PASSWORD` for the
  detection service.
- `TRUST_FORWARDED_FOR=true` lets the simulator spoof source IPs. Set it to `false` unless the app sits
  behind a trusted proxy.
- Secrets live only in `.env` (git-ignored). Analyst accounts are in-memory demo users. Use an
  identity provider (OIDC) in real deployments.
- PostgreSQL, incident-tracker and detection-service publish no host ports. The dashboard's nginx
  is the only way in.

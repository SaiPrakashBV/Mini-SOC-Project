# Attack simulators

Six independent attack campaigns against the target app. Each one plays a different
kind of attacker, uses fresh random attacker IPs on every run, and prints the
detections you should see in the dashboard afterwards.

| # | Script | Attacker | Techniques | Expected detections |
|---|---|---|---|---|
| 1 | `1_credential_stuffing.py` | Botnet with a leaked password list | IP-rotating brute force, combo-list replay, account takeover of `admin`, bulk data theft | `DISTRIBUTED_BRUTE_FORCE`, `BRUTE_FORCE_LOGIN`, `PASSWORD_SPRAY`, `ACCOUNT_TAKEOVER` (CRITICAL), `DATA_SCRAPING` |
| 2 | `2_vulnerability_scanner.py` | Automated scanner (Nikto) | 30 sensitive-path probes, 36 injection payloads, ID brute forcing (~125 requests) | `SCANNER_TOOL`, `RECON_PATH_SCAN`, `INJECTION_ATTEMPT` (CRITICAL), `HIGH_REQUEST_RATE`, `AUTH_ERROR_SPIKE` |
| 3 | `3_insider_threat.py` | Employee `bob` on the office network | Normal session, admin probing, reading other customers' orders, bulk export | `RESTRICTED_ENDPOINT_ACCESS`, `IDOR_ATTEMPT`, `DATA_SCRAPING` |
| 4 | `4_session_hijack.py` | Infostealer operator | alice's JWT replayed from 5 Tor/proxy IPs, claims tampered to ROLE_ADMIN, `alg=none` forgery | `SESSION_HIJACK`, `INVALID_TOKEN_ABUSE`, `JWT_ALG_NONE`, `AUTH_ERROR_SPIKE` |
| 5 | `5_log4shell_campaign.py` | 3 mass-exploitation bots | Obfuscated `${jndi:...}` payloads in 5 headers + params, RCE droppers | `LOG4SHELL_EXPLOIT` ×3 (CRITICAL), `INJECTION_ATTEMPT` ×3 |
| 6 | `6_ddos_flood.py` | 4 flooding hosts | 640 concurrent requests, login flood with random accounts | `HIGH_REQUEST_RATE` ×4, `AUTH_ERROR_SPIKE` ×4, `PASSWORD_SPRAY` ×4 |

## Running

Start the stack first (`docker compose up -d`). Then use either option.

**Option A: with Docker (no Python needed).** Works the same on Windows, macOS and Linux:

```bash
docker compose run --rm attacker 1_credential_stuffing.py
```

Replace the file name to run any other simulator.

**Option B: with a local Python 3.9+.** It uses the standard library only, so no `pip install` is needed.
Run it from the project folder:

```bash
python attack-simulators/1_credential_stuffing.py
```

On Windows, `py attack-simulators\1_credential_stuffing.py` also works. The scripts read the demo
passwords from `.env` and target `http://localhost:8080`. Set `TARGET` to point somewhere else.

Then open the dashboard at http://localhost:3000. Alerts appear within about 20 seconds; on
*Alerts & Rules*, **Run detection now** skips the wait.

## Running a simulator again

- **Rules grouped by IP** (`ACCOUNT_TAKEOVER`, `SCANNER_TOOL`, `LOG4SHELL_EXPLOIT`, …) create new
  incidents every run, because the attacker IPs are random each time.
- **Rules grouped by user** (`BRUTE_FORCE_LOGIN` on alice, `IDOR_ATTEMPT` on bob, …) are quiet for
  the rule's window after firing (1-10 minutes, see `detection-service` `application.yml`). After that,
  a repeat detection is added to the *existing* open incident: its hit count goes up instead of a
  duplicate being created. To get a fresh incident, resolve or close the old one first.

Only run these against your own lab.

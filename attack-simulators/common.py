"""Shared helpers for the Mini SOC attack simulators.

Standard library only, so the simulators run anywhere Python 3.9+ is installed,
or inside the `attacker` Docker Compose service (see README.md in this folder).

Only run these against your own lab environment.
"""
import base64
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

if os.name == "nt":
    os.system("")  # enables ANSI colours in the Windows console

CYAN, YELLOW, GREEN, RED, BOLD, DIM, RESET = (
    "\033[36m", "\033[33m", "\033[32m", "\033[31m", "\033[1m", "\033[2m", "\033[0m")

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/129.0 Safari/537.36")


# ----------------------------------------------------------------------- config
def _load_env():
    values = {}
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    values.update({k: v for k, v in os.environ.items() if k.startswith(("DEMO_", "TARGET"))})
    return values


CONFIG = _load_env()
TARGET = os.environ.get("TARGET") or f"http://localhost:{CONFIG.get('TARGET_APP_PORT', '8080')}"
DASHBOARD = f"http://localhost:{CONFIG.get('DASHBOARD_PORT', '3000')}"


def password(user):
    key = f"DEMO_{user.upper()}_PASSWORD"
    if key not in CONFIG:
        sys.exit(f"{RED}{key} not found - create .env first (scripts/generate-env.*){RESET}")
    return CONFIG[key]


# ------------------------------------------------------------------------- http
def request(method, path, ip, token=None, body=None, user_agent=BROWSER_UA, headers=None, query=None):
    """Sends one request as if it came from `ip` and returns (status, parsed JSON body or None)."""
    url = TARGET + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-Forwarded-For", ip)
    req.add_header("User-Agent", user_agent)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            return res.status, _json(res.read())
    except urllib.error.HTTPError as e:
        return e.code, _json(e.read())
    except urllib.error.URLError as e:
        sys.exit(f"{RED}Cannot reach {TARGET} ({e.reason}). Is the stack running? "
                 f"Try: docker compose ps{RESET}")


def _json(raw):
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None


def login(user, pwd, ip, user_agent=BROWSER_UA):
    status, body = request("POST", "/api/auth/login", ip, body={"username": user, "password": pwd},
                           user_agent=user_agent)
    return status, (body or {}).get("accessToken")


def parallel(fn, items, workers=20):
    """Runs fn(item) concurrently and returns the list of results."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fn, items))


# -------------------------------------------------------------------------- jwt
def b64url(data):
    raw = json.dumps(data, separators=(",", ":")).encode() if isinstance(data, dict) else data
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt_claims(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


# ---------------------------------------------------------------------- helpers
def random_ip(prefixes=("45.", "91.", "103.", "185.", "193.", "194.", "198.51.100.", "203.0.113.")):
    """A random public-looking attacker IP, different on every run."""
    prefix = random.choice(prefixes)
    parts = prefix.rstrip(".").split(".")
    while len(parts) < 4:
        parts.append(str(random.randint(1, 254)))
    return ".".join(parts)


def banner(title, story):
    print(f"\n{BOLD}{CYAN}{'=' * 72}\n  {title}\n{'=' * 72}{RESET}")
    print(f"{DIM}{story}{RESET}")
    print(f"{DIM}Target: {TARGET}{RESET}")


def stage(number, text):
    print(f"\n{BOLD}{YELLOW}[stage {number}]{RESET} {text}")


def report(label, statuses):
    counts = Counter(statuses)
    summary = "  ".join(f"{_colour(code)}{code}{RESET} x{n}" for code, n in sorted(counts.items()))
    print(f"   {label:<46} {summary}")


def _colour(code):
    return GREEN if code < 400 else YELLOW if code in (400, 401, 403, 404) else RED


def pause(seconds, why):
    print(f"   {DIM}... {why} ({seconds}s){RESET}")
    time.sleep(seconds)


def finish(expected_rules):
    print(f"\n{BOLD}{GREEN}Attack complete.{RESET} Expected detections:")
    for rule, why in expected_rules:
        print(f"   {BOLD}{rule:<28}{RESET} {why}")
    print(f"\n{DIM}Events reach OpenSearch in ~5s and rules run every 15s.{RESET}")
    print(f"Watch it in the dashboard: {BOLD}{DASHBOARD}{RESET}  "
          f"{DIM}(Alerts & Rules -> 'Run detection now' to skip the wait){RESET}\n")

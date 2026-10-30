"""Simulator 6 - Layer-7 DDoS / API abuse.

Several hosts flood the API at the same time: unauthenticated hammering of data
endpoints plus a login flood with random accounts to burn server CPU (every
login attempt costs a bcrypt hash).
"""
import random
import string
import time

from common import banner, finish, parallel, random_ip, report, request, stage

ENDPOINTS = ["/api/orders", "/api/users/me", "/api/orders/1001", "/api/admin/stats"]
REQUESTS_PER_HOST = 160
LOGINS_PER_HOST = 15


def flood(ip):
    def hit(i):
        if i < LOGINS_PER_HOST:
            user = "".join(random.choices(string.ascii_lowercase, k=8))
            return request("POST", "/api/auth/login", ip, body={"username": user, "password": "x" * 12},
                           user_agent="python-requests/2.32")[0]
        return request("GET", random.choice(ENDPOINTS), ip, user_agent="python-requests/2.32")[0]
    return parallel(hit, range(REQUESTS_PER_HOST), workers=25)


def main():
    hosts = [random_ip() for _ in range(4)]
    banner("SIMULATOR 6 - Layer-7 DDoS / API abuse",
           f"{len(hosts)} hosts x {REQUESTS_PER_HOST} requests at once, including a login flood.")

    stage(1, f"Flooding from {', '.join(hosts)}")
    start = time.time()
    results = parallel(flood, hosts, workers=len(hosts))
    elapsed = time.time() - start
    for ip, statuses in zip(hosts, results):
        report(f"{ip}", statuses)
    total = sum(len(r) for r in results)
    print(f"   {total} requests in {elapsed:.1f}s ({total / max(elapsed, 0.1):.0f} req/s)")

    finish([
        ("HIGH_REQUEST_RATE", f"one alert per host ({len(hosts)} x {REQUESTS_PER_HOST} requests/min)"),
        ("AUTH_ERROR_SPIKE", "each host gets 100+ 401/403 responses (HIGH at 60+)"),
        ("PASSWORD_SPRAY", f"{LOGINS_PER_HOST} failed logins per host"),
    ])


if __name__ == "__main__":
    main()

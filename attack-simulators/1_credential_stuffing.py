"""Simulator 1 - Credential-stuffing botnet.

A botnet replays a leaked username/password list. Part of the botnet rotates IPs
against one high-value account; one bot works through the combo list until a
password reused from another breach works, then logs in and bulk-downloads data.
"""
import random

from common import (banner, finish, login, parallel, password, random_ip, report, request, stage)

LEAKED_PASSWORDS = ["123456", "Password1!", "qwerty123", "Welcome2026", "letmein", "iloveyou1",
                    "Summer2026!", "P@ssw0rd", "admin123", "Football99", "Monkey!23", "Dragon2026"]
LEAKED_USERS = ["alice", "bob", "admin", "jsmith", "mwilson", "support", "test", "ceo",
                "hr.manager", "devops", "backup", "guest"]


def main():
    banner("SIMULATOR 1 - Credential-stuffing botnet",
           "Leaked credentials replayed from many IPs, ending in an account takeover and data theft.")

    stage(1, "Botnet rotates through 7 IPs, one attempt each against 'alice'")
    botnet = [random_ip() for _ in range(7)]
    statuses = parallel(lambda ip: login("alice", random.choice(LEAKED_PASSWORDS), ip)[0], botnet)
    report("distributed attempts on alice", statuses)

    stage(2, "One bot replays 12 leaked combos, then hits the admin's reused password")
    bot = random_ip()
    print(f"   bot IP: {bot}")
    statuses = [login(u, random.choice(LEAKED_PASSWORDS), bot)[0] for u in LEAKED_USERS]
    report("combo list (wrong passwords)", statuses)
    status, token = login("admin", password("admin"), bot)
    report("admin - reused password", [status])

    stage(3, "Attacker uses the admin session to dump every customer's orders 45 times (data theft)")
    statuses = parallel(lambda _: request("GET", "/api/orders", bot, token=token)[0], range(45), workers=5)
    report("GET /api/orders as admin", statuses)
    statuses = [request("GET", "/api/users", bot, token=token)[0], request("GET", "/api/admin/stats", bot, token=token)[0]]
    report("GET /api/users + /api/admin/stats", statuses)

    finish([
        ("DISTRIBUTED_BRUTE_FORCE", "alice attacked from 7 different IPs"),
        ("PASSWORD_SPRAY", f"12 failed logins from {bot}"),
        ("ACCOUNT_TAKEOVER", f"failures followed by a successful login from {bot} (CRITICAL)"),
        ("BRUTE_FORCE_LOGIN", "alice: 7 failures in 2 minutes"),
        ("DATA_SCRAPING", "admin account read /api/orders 45 times in a minute"),
    ])


if __name__ == "__main__":
    main()

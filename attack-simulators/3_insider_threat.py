"""Simulator 3 - Malicious insider.

A legitimate employee (bob) logs in normally from the office network, then starts
looking for things they should not see: admin functions, other customers' orders,
and finally a bulk export of everything they can reach.
"""
import random

from common import banner, finish, login, password, report, request, stage, pause


def main():
    banner("SIMULATOR 3 - Malicious insider",
           "A valid user abuses their access: privilege probing, IDOR enumeration, bulk export.")
    office_ip = f"10.20.{random.randint(1, 254)}.{random.randint(1, 254)}"
    print(f"   insider: bob @ {office_ip} (corporate network)")

    stage(1, "Normal working session - looks completely legitimate")
    status, token = login("bob", password("bob"), office_ip)
    statuses = [status]
    for _ in range(3):
        statuses.append(request("GET", "/api/orders", office_ip, token=token)[0])
        statuses.append(request("GET", "/api/users/me", office_ip, token=token)[0])
    report("login + normal browsing", statuses)
    pause(2, "insider gets curious")

    stage(2, "Probing privileged functions")
    probes = [("GET", "/api/admin/stats"), ("GET", "/api/users"), ("POST", "/api/admin/maintenance"),
              ("GET", "/api/admin/stats"), ("GET", "/api/admin/users"), ("DELETE", "/api/admin/stats")]
    statuses = [request(m, p, office_ip, token=token)[0] for m, p in probes]
    report("admin endpoint attempts (403 = denied)", statuses)

    stage(3, "Enumerating other customers' orders (IDOR)")
    statuses = [request("GET", f"/api/orders/{order_id}", office_ip, token=token)[0]
                for order_id in [1001, 1002, 1001, 1002, 1005, 1006, 1001]]
    report("reading orders 1001-1006 (403 = not bob's)", statuses)

    stage(4, "Bulk export before leaving the company")
    statuses = [request("GET", "/api/orders", office_ip, token=token)[0] for _ in range(25)]
    statuses += [request("GET", f"/api/orders/{oid}", office_ip, token=token)[0]
                 for oid in [1003, 1004] * 10]
    report("export loop", statuses)

    finish([
        ("RESTRICTED_ENDPOINT_ACCESS", "bob repeatedly denied on /api/admin"),
        ("IDOR_ATTEMPT", "bob requested orders belonging to alice"),
        ("DATA_SCRAPING", "bob read 45+ order records within a minute"),
    ])


if __name__ == "__main__":
    main()

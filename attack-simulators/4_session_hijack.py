"""Simulator 4 - Stolen session and token forgery.

alice logs in normally. Her JWT is stolen (e.g. by malware or an XSS bug) and
replayed from anonymising proxies around the world. The attacker then tries to
turn it into an admin token: first by editing the claims, then by stripping the
signature entirely (alg=none).
"""
import random

from common import (b64url, banner, finish, jwt_claims, login, password, random_ip, report, request,
                    stage, pause)


def main():
    banner("SIMULATOR 4 - Stolen session & token forgery",
           "A valid JWT is replayed from several countries, then tampered with to gain admin rights.")
    home_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"

    stage(1, f"alice logs in from home ({home_ip}) and works normally")
    status, token = login("alice", password("alice"), home_ip)
    statuses = [status] + [request("GET", "/api/orders", home_ip, token=token)[0] for _ in range(3)]
    report("normal session", statuses)
    print(f"   token id (jti): {jwt_claims(token)['jti']}")
    pause(2, "token is exfiltrated by infostealer malware")

    stage(2, "Stolen token replayed from 5 proxy/Tor exit IPs")
    proxies = [random_ip(("185.220.", "171.25.", "109.70.", "199.249.", "45.")) for _ in range(5)]
    statuses = []
    for ip in proxies:
        statuses.append(request("GET", "/api/orders", ip, token=token)[0])
        statuses.append(request("GET", "/api/users/me", ip, token=token)[0])
    report("replayed requests (200 = token accepted)", statuses)
    print(f"   used from: {', '.join(proxies)}")

    attacker = proxies[0]
    stage(3, f"Privilege escalation: claims edited to ROLE_ADMIN, original signature kept ({attacker})")
    header, _, signature = token.split(".")
    claims = jwt_claims(token)
    statuses = []
    for i in range(14):
        forged = dict(claims, roles=["ROLE_USER", "ROLE_ADMIN"], sub=random.choice(["alice", "admin"]),
                      exp=claims["exp"] + 86400 * (i + 1))
        statuses.append(request("GET", "/api/admin/stats", attacker, token=f"{header}.{b64url(forged)}.{signature}")[0])
    report("tampered tokens (401 = signature check failed)", statuses)

    stage(4, "Signature stripped: alg=none token claiming admin")
    unsigned = f"{b64url({'alg': 'none', 'typ': 'JWT'})}.{b64url(dict(claims, sub='admin', roles=['ROLE_ADMIN']))}."
    statuses = [request("GET", p, attacker, token=unsigned)[0] for p in ("/api/admin/stats", "/api/users")]
    report("alg=none tokens (401 = rejected)", statuses)

    finish([
        ("SESSION_HIJACK", f"one token used from {len(proxies) + 1} different IPs"),
        ("INVALID_TOKEN_ABUSE", f"14 tampered JWTs from {attacker}"),
        ("JWT_ALG_NONE", "unsigned token presented"),
        ("AUTH_ERROR_SPIKE", "burst of 401s from the attacker IP"),
    ])


if __name__ == "__main__":
    main()

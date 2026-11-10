"""Check local_rules.xml against sample log lines through the manager's logtest socket.

Run on the server (stdlib only; uses the Python bundled in the manager image):
    cd infra/wazuh
    docker compose exec -T wazuh.manager /var/ossec/framework/python/bin/python3 - < ../../wazuh/tests/test_rules.py

Each case runs in its own logtest session, so frequency counters start empty.
Logtest evaluates events as they arrive, so all events of a case fall inside
the rule timeframes.
"""
import json
import socket
import struct
import sys

SOCKET = "/var/ossec/queue/sockets/logtest"
DIRECT = "/var/log/kmam/nginx/access-direct.log"
CF = "/var/log/kmam/nginx/access-cf.log"
AUTH = "/var/log/kmam/app/auth.json"


def access(ip, status, url="/login", method="POST"):
    size = {200: 3, 401: 20}.get(status, 19)
    return (f'{ip} - - [10/Nov/2026:03:08:46 +0000] "{method} {url} HTTP/1.1" '
            f'{status} {size} "-" "curl/8.22.0"')


def auth(msg, user, ip):
    return json.dumps({"time": "2026-11-10T03:08:46.000000000Z", "level": "INFO",
                       "msg": msg, "user": user, "srcip": ip}, separators=(",", ":"))


A, B = "203.0.113.10", "203.0.113.20"
IPS = [f"198.51.100.{i}" for i in range(1, 7)]

# (name, location, log_format, [(event, expected rule id)])
CASES = [
    ("direct: one 401 on /login", DIRECT, "syslog", [(access(A, 401), "100100")]),
    ("cf: one 401 on /login", CF, "syslog", [(access(A, 401), "100110")]),
    ("direct: 401 on another URL is not a login failure", DIRECT, "syslog",
     [(access(A, 401, url="/admin"), "31101")]),
    ("direct: 10 failures from one IP -> 100101 on the 10th", DIRECT, "syslog",
     [(access(A, 401), "100100")] * 9 + [(access(A, 401), "100101")]),
    ("cf: 10 failures from one IP -> 100111 on the 10th", CF, "syslog",
     [(access(A, 401), "100110")] * 9 + [(access(A, 401), "100111")]),
    ("direct: 5 + 5 failures from two IPs -> no 100101", DIRECT, "syslog",
     [(access(ip, 401), "100100") for ip in [A, B] * 5]),
    ("direct: success without prior brute force -> 100102", DIRECT, "syslog",
     [(access(A, 200), "100102")]),
    ("direct: brute force then success from same IP -> 100105 (E1)", DIRECT, "syslog",
     [(access(A, 401), None)] * 10 + [(access(A, 200), "100105")]),
    ("cf: brute force then success from same IP -> 100105 (E1)", CF, "syslog",
     [(access(A, 401), None)] * 10 + [(access(A, 200), "100105")]),
    ("direct: brute force from A, success from B -> 100102", DIRECT, "syslog",
     [(access(A, 401), None)] * 10 + [(access(B, 200), "100102")]),
    ("app: login_failed -> 100120", AUTH, "json", [(auth("login_failed", "admin", A), "100120")]),
    ("app: login_success is not 100120", AUTH, "json",
     [(auth("login_success", "admin", A), "!100120")]),
    ("app: 6 failures, same user, 6 IPs -> 100121 on the 6th (E2)", AUTH, "json",
     [(auth("login_failed", "admin", ip), "100120") for ip in IPS[:5]]
     + [(auth("login_failed", "admin", IPS[5]), "100121")]),
    ("app: 6 failures, same user, one IP -> no 100121", AUTH, "json",
     [(auth("login_failed", "admin", A), "100120")] * 6),
    ("app: 6 failures, 6 users, 6 IPs -> no 100121", AUTH, "json",
     [(auth("login_failed", f"user{i}", ip), "100120") for i, ip in enumerate(IPS)]),
    # Known limitation: different_srcip only compares each earlier event with the
    # current one, so two IPs are enough to trigger E2.
    ("app: 5 failures from A then 1 from B -> 100121 (different_srcip limitation)", AUTH, "json",
     [(auth("login_failed", "admin", A), "100120")] * 5
     + [(auth("login_failed", "admin", B), "100121")]),
]


def call(command, parameters):
    msg = json.dumps({"version": 1, "origin": {"name": "kmam-tests", "module": "wazuh-logtest"},
                      "command": command, "parameters": parameters}).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCKET)
        s.sendall(struct.pack("<I", len(msg)) + msg)
        size = struct.unpack("<I", s.recv(4, socket.MSG_WAITALL))[0]
        return json.loads(s.recv(size, socket.MSG_WAITALL))


def main():
    failed = 0
    for name, location, log_format, events in CASES:
        token, errors = None, []
        for i, (event, want) in enumerate(events, 1):
            params = {"event": event, "log_format": log_format, "location": location}
            if token:
                params["token"] = token
            resp = call("log_processing", params)
            if resp.get("error"):
                errors.append(f"event {i}: logtest error {resp}")
                break
            token = resp["data"]["token"]
            got = resp["data"]["output"].get("rule", {}).get("id")
            if want is None:
                continue
            ok = got != want[1:] if want.startswith("!") else got == want
            if not ok:
                errors.append(f"event {i}: rule {got}, want {want}")
        if token:
            call("remove_session", {"token": token})
        print(("FAIL " if errors else "ok   ") + name)
        for e in errors:
            print("     " + e)
        failed += bool(errors)
    print(f"{len(CASES) - failed}/{len(CASES)} cases passed")
    sys.exit(1 if failed else 0)


main()

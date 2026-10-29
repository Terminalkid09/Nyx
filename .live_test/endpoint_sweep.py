"""Read-only sweep of the Nyx API + targeted writes used by the desktop app."""
import json
import os
import sys
import uuid

import httpx

BASE = os.environ.get("NYX_BASE", "http://127.0.0.1:8000")
SESSION = str(uuid.uuid4())
ZERO = "00000000-0000-0000-0000-000000000001"

# Endpoints that change the host (certificates, capture, network exports).
SKIP = {
    "/api/shutdown",
    "/api/ca-uninstall",
    "/api/ca-uninstall-qr",
    "/api/ca/remove",
    "/api/backup",
    "/api/mitm/scan-network",
    "/api/mitm/start",
    "/api/mitm/stop",
    "/api/mitm/tls",
    "/api/mitm/quic",
    "/api/mitm/udp",
    "/api/mitm/udp/clear",
    "/api/network/capture/start",
    "/api/network/capture/stop",
    "/api/network/export",
    "/api/requests/export/har",
    "/api/export/findings",
    "/api/proxy/capture",
    "/api/settings/proxy",
}


def placeholder(path: str) -> str:
    return (
        path.replace("{session_id}", SESSION)
        .replace("{job_id}", ZERO)
        .replace("{profile_id}", ZERO)
        .replace("{rule_id}", ZERO)
        .replace("{finding_id}", ZERO)
        .replace("{check_id}", ZERO)
        .replace("{policy_id}", ZERO)
        .replace("{project_id}", ZERO)
        .replace("{proxy_id}", ZERO)
        .replace("{item_id}", ZERO)
        .replace("{config_id}", ZERO)
        .replace("{tab_id}", ZERO)
        .replace("{msg_id}", ZERO)
        .replace("{cookie_id}", ZERO)
        .replace("{schedule_id}", ZERO)
        .replace("{template_id}", ZERO)
        .replace("{webhook_id}", ZERO)
        .replace("{pipeline_id}", ZERO)
        .replace("{filename}", "nope.json")
        .replace("{name}", "content_discovery.txt")
        .replace("{seq}", "1")
        .replace("{stream_id}", "1")
        .replace("{request_id}", ZERO)
    )


def main() -> int:
    client = httpx.Client(timeout=20)
    health = client.get(f"{BASE}/health")
    print("health:", health.status_code)
    client.post(f"{BASE}/api/sessions", json={"name": "sweep"})

    spec = client.get(f"{BASE}/openapi.json").json()
    failures = []
    results = {}
    for path, ops in sorted(spec["paths"].items()):
        if "get" not in ops or path in SKIP or path.startswith("/api/ca"):
            continue
        url = BASE + placeholder(path)
        try:
            response = client.get(url)
        except Exception as exc:  # noqa: BLE001 — report, don't abort the sweep
            failures.append((path, "EXC", str(exc)[:120]))
            continue
        results[response.status_code] = results.get(response.status_code, 0) + 1
        # 404/422 are the honest answers for the zero-UUID placeholders and for
        # reads that need query parameters the sweep does not supply. Only a
        # server error (or a method that the router does not accept at all,
        # which usually means a mount swallowed the route) is a real failure.
        if response.status_code >= 500 or response.status_code == 405:
            failures.append((path, response.status_code, response.text[:160]))

    expected = results.get(404, 0) + results.get(422, 0)
    print("GET status distribution:", dict(sorted(results.items())))
    print(f"expected placeholder answers: {expected} (404/422)")
    if failures:
        print(f"\nFAILURES ({len(failures)}):")
        for item in failures:
            print(" ", item)
    else:
        print("no 5xx across GET endpoints")

    # Targeted write paths used by the desktop UI.
    checks = []

    def call(name, method, path, **kwargs):
        try:
            response = client.request(method, BASE + path, **kwargs)
            body = response.text[:120].replace("\n", " ")
            checks.append((name, response.status_code, body))
        except Exception as exc:  # noqa: BLE001
            checks.append((name, "EXC", str(exc)[:120]))

    call("scope check", "POST", "/api/scope/check",
         json={"session_id": SESSION, "url": "http://127.0.0.1:8099/"})
    call("scope create", "POST", "/api/scope/",
         json={"session_id": SESSION, "name": "sweep", "rule_type": "include",
               "pattern": "127.0.0.1", "is_regex": False})
    call("decoder hash", "POST", "/api/decoder/hash",
         json={"input": "abc", "algorithm": "md5"})
    call("decoder smart", "POST", "/api/decoder/smart-decode",
         json={"input": "aGVsbG8=", "text": "aGVsbG8="})
    call("jwt decode", "POST", "/api/auth/jwt/decode",
         json={"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."})
    call("comparer add", "POST", "/api/comparer/items",
         json={"session_id": SESSION, "left_content": "GET / HTTP/1.1",
               "right_content": "GET /x HTTP/1.1"})
    call("organizer add", "POST", "/api/organizer/",
         json={"session_id": SESSION, "title": "sweep"})
    call("repeater tab", "POST", "/api/repeater/tabs",
         json={"name": "sweep", "request": {"method": "GET", "url": "http://127.0.0.1:8099/"}})
    call("verifier", "POST", "/api/auto-exploit/verify",
         json={"url": "http://127.0.0.1:8099/?q=1", "method": "GET", "headers": {}})
    call("attack path", "GET", f"/api/attack-path/{SESSION}")
    call("fuzzer preview", "POST", "/api/fuzzer/preview",
         json={"request_template": "GET /?q=§x§ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
               "positions": [{"name": "x", "wordlist_path": "common.txt"}],
               "attack_type": "sniper"})
    call("scan policy", "POST", "/api/scan-policies",
         json={"name": "sweep", "description": "", "config": {}})
    call("project", "POST", "/api/projects",
         json={"name": "sweep", "description": ""})
    call("roe create", "POST", "/api/roe",
         json={"name": "sweep-roe", "targets": ["127.0.0.1"], "max_rps": 0})
    call("wordlist upload", "POST", "/api/content-discovery/wordlists/upload",
         json={"name": "sweep_list.txt", "content": "a\nb\n"})

    print("\nTARGETED WRITES:")
    for name, status, body in checks:
        print(f"  {name}: {status} {body}")

    # cleanup the uploaded list
    client.delete(f"{BASE}/api/content-discovery/wordlists/sweep_list.txt")
    client.close()

    bad = [c for c in checks if c[1] == "EXC" or (isinstance(c[1], int) and (c[1] >= 500 or c[1] == 405))]
    return 1 if failures or bad else 0


if __name__ == "__main__":
    sys.exit(main())

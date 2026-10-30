"""Live regression for the security fixes reported by the external review.

Each check reproduces a bypass that the v1.0.0 pass demonstrated, and asserts
the endpoint now refuses it. Part A runs against a normal (dev) backend; part B
runs only in token mode (start the backend with API_REQUIRE_SESSION_TOKEN=true)
and covers the WebSocket and /api/auth/key.

    python .live_test/security_regression.py            # dev mode
    NYX_TOKEN=<value> python .live_test/security_regression.py   # token mode
"""
import json
import os
import socket
import sys
import time

import httpx

BASE = os.environ.get("NYX_BASE", "http://127.0.0.1:8000")
TARGET = os.environ.get("NYX_TARGET", "http://127.0.0.1:8099")
TOKEN = os.environ.get("NYX_TOKEN", "")

HEADERS = {"X-Nyx-Token": TOKEN} if TOKEN else {}
checks: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str) -> None:
    checks.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + " — " + str(detail)[:220])


def post(path: str, payload, expect: int | tuple[int, ...], name: str):
    try:
        response = httpx.post(BASE + path, json=payload, headers=HEADERS, timeout=60)
    except Exception as exc:  # noqa: BLE001
        record(name, False, f"EXC {exc}")
        return None
    expected = expect if isinstance(expect, tuple) else (expect,)
    record(name, response.status_code in expected,
           f"{response.status_code} {response.text[:180]}")
    return response


def new_session(client: httpx.Client, name: str) -> str:
    response = client.post(BASE + "/api/sessions", json={"name": name}, headers=HEADERS)
    response.raise_for_status()
    return response.json()["id"]


def add_rule(client: httpx.Client, session_id: str, pattern: str) -> None:
    client.post(
        BASE + "/api/scope/",
        json={
            "session_id": session_id, "name": pattern, "rule_type": "include",
            "pattern": pattern, "is_regex": False, "enabled": True,
        },
        headers=HEADERS,
    ).raise_for_status()


def base_request() -> dict:
    return {
        "method": "GET",
        "url": TARGET + "/sqli?id=1",
        "headers": {"Host": "127.0.0.1"},
        "content": None,
    }


def part_a() -> None:
    client = httpx.Client(timeout=60, headers=HEADERS)
    scoped = new_session(client, "regression-out")
    add_rule(client, scoped, "192.0.2.10")
    allowed = new_session(client, "regression-in")
    add_rule(client, allowed, "127.0.0.1")

    # 1. Omitting session_id must no longer skip the scope gate. The schema
    #    rejects the body before the route runs (422); the route itself answers
    #    400 when the field is present but null.
    post(
        "/api/active-scanner/run",
        {"base_request": base_request(), "target_params": ["id"], "checks": ["active_sqli"]},
        (400, 422),
        "active scan without session_id is refused",
    )
    post(
        "/api/active-scanner/run",
        {
            "base_request": base_request(), "target_params": ["id"],
            "checks": ["active_sqli"], "session_id": scoped,
        },
        403,
        "active scan from an out-of-scope session is refused",
    )
    scanned = post(
        "/api/active-scanner/run",
        {
            "base_request": base_request(), "target_params": ["id"],
            "checks": ["active_sqli"], "session_id": allowed,
        },
        200,
        "active scan from the in-scope session still runs",
    )
    if scanned is not None:
        record(
            "in-scope scan still finds the SQL injection",
            scanned.json().get("total", 0) >= 1,
            str(scanned.json())[:180],
        )

    # 2. The other endpoints that fire real requests.
    post(
        "/api/auto-exploit/verify",
        {"url": TARGET + "/sqli?id=1", "method": "GET"},
        (400, 422),
        "verify without session_id is refused",
    )
    post(
        "/api/repeater/send",
        {"method": "GET", "url": TARGET + "/"},
        (400, 422),
        "repeater send without session_id is refused",
    )
    post(
        "/api/crawler/start",
        {"start_url": TARGET + "/", "max_pages": 2},
        (400, 422),
        "crawler start without session_id is refused",
    )
    post(
        "/api/content-discovery/start",
        {
            "target_url": TARGET + "/",
            "wordlist_path": ".live_test/wordlist.txt",
        },
        (400, 422),
        "content discovery without session_id is refused",
    )
    post(
        "/api/ab-test/run",
        {
            "url": TARGET + "/", "identity_a": {"name": "a"},
            "identity_b": {"name": "b"},
        },
        (400, 422),
        "A/B replay without session_id is refused",
    )

    # 3. /api/scope/check must answer for the given session only.
    preview = post(
        "/api/scope/check",
        {"session_id": scoped, "url": TARGET + "/"},
        200,
        "scope check answers",
    )
    if preview is not None:
        body = preview.json()
        record(
            "scope check ignores another session's rule",
            body.get("in_scope") is False,
            json.dumps(body)[:180],
        )
    inside = post(
        "/api/scope/check",
        {"session_id": allowed, "url": TARGET + "/"},
        200,
        "scope check answers for the covering session",
    )
    if inside is not None:
        record(
            "scope check allows the target in its own session",
            inside.json().get("in_scope") is True,
            json.dumps(inside.json())[:180],
        )

    # 4. Burp import: a DOCTYPE padded past the old 4096-byte window.
    padded = (
        "<?xml version=\"1.0\"?>\n<!--" + ("A" * 6000) + "-->\n"
        "<!DOCTYPE items [<!ENTITY x \"y\">]><items></items>"
    )
    response = client.post(
        BASE + "/api/import/burp", json={"document": padded}, timeout=60
    )
    record(
        "Burp import rejects a padded DOCTYPE",
        response.status_code == 400,
        f"{response.status_code} {response.text[:160]}",
    )

    # 5. A loopback sweep must not trip the rate limiter any more.
    statuses = {}
    for _ in range(400):
        code = httpx.get(BASE + "/api/sessions", headers=HEADERS, timeout=20).status_code
        statuses[code] = statuses.get(code, 0) + 1
    record(
        "400 loopback GETs stay under the rate limit",
        statuses.get(429, 0) == 0,
        str(statuses),
    )
    client.close()


def ws_status(token: str | None) -> str:
    """Raw WebSocket upgrade: no third-party client needed."""
    parsed = httpx.URL(BASE)
    host, port = parsed.host, parsed.port or 80
    path = "/ws/traffic" + (f"?token={token}" if token else "")
    try:
        sock = socket.create_connection((host, port), timeout=10)
    except OSError as exc:
        return f"EXC {exc}"
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    try:
        sock.sendall(request.encode("ascii"))
        return sock.recv(64).decode("latin-1").split("\r\n")[0]
    except OSError as exc:
        return f"EXC {exc}"
    finally:
        sock.close()


def part_b() -> None:
    client = httpx.Client(timeout=60)
    anon = client.get(BASE + "/api/auth/key")
    record("/api/auth/key requires the token", anon.status_code == 403,
           f"{anon.status_code} {anon.text[:120]}")
    with_token = client.get(BASE + "/api/auth/key", headers={"X-Nyx-Token": TOKEN})
    record("/api/auth/key answers with the token", with_token.status_code == 200,
           str(with_token.status_code))

    record("WebSocket upgrade without a token is refused",
           not ws_status(None).startswith("HTTP/1.1 101"), ws_status(None))
    record("WebSocket upgrade with the token is accepted",
           ws_status(TOKEN).startswith("HTTP/1.1 101"), ws_status(TOKEN))
    client.close()


def main() -> int:
    health = httpx.get(BASE + "/health", timeout=20)
    print("health:", health.status_code, json.dumps(health.json())[:120])
    part_a()
    if TOKEN:
        part_b()
    else:
        print("(token mode not enabled: WebSocket/token checks skipped)")

    failed = [c for c in checks if not c[1]]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    for name, _, detail in failed:
        print("  FAILED:", name, "—", str(detail)[:200])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

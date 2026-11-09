"""Privileged / host-changing endpoints of the Nyx API, live.

These are exactly the routes the read-only sweep skips because they touch the
machine (certificates, firewall/QUIC/UDP policy, capture, transparent
redirect) or because they need Administrator. Every step restores the state it
changed; the last step exercises the graceful shutdown endpoint.

Run it against a backend started as Administrator (launch Nyx elevated):

    python .live_test/privileged_sweep.py
"""
import os
import subprocess
import sys
import time
import uuid

import httpx

BASE = os.environ.get("NYX_BASE", "http://127.0.0.1:8000")
PROBE_TARGET = "192.0.2.10"   # TEST-NET-1: a valid ARP/DHCP target nobody owns
OUTSIDE_SESSION = str(uuid.uuid4())

client = httpx.Client(timeout=90)
checks: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail[:240]}" if detail else ""))


def call(name, method, path, expect=(200,), **kwargs):
    try:
        response = client.request(method, BASE + path, **kwargs)
    except Exception as exc:  # noqa: BLE001
        record(name, False, f"EXC {exc}")
        return None
    body = None
    try:
        body = response.json()
    except ValueError:
        body = response.text[:200]
    ok = response.status_code in expect
    record(name, ok, f"{response.status_code} {str(body)[:180]}")
    return body if ok else None


def main() -> int:
    health = client.get(BASE + "/health")
    record("health", health.status_code == 200, str(health.status_code))
    status = client.get(BASE + "/api/mitm/status").json()
    elevated = bool(status.get("admin_mode"))
    if elevated:
        record("backend runs elevated", True, "admin_mode=True")
    else:
        # Informational: this run covers everything that does not need raw
        # sockets, so it must not turn an unelevated machine into a red run.
        print("NOTE backend is not elevated: ARP/DHCP/NDP redirect checks are skipped")

    proxy_before = client.get(BASE + "/api/settings/proxy").json()
    capture_before = client.get(BASE + "/api/proxy/capture").json()

    # ── proxy settings (restarts the proxy engine) ────────────────────────
    call("settings proxy rejects bad mode", "PUT", "/api/settings/proxy",
         expect=(400, 422), json={"host": proxy_before["host"],
                                  "port": proxy_before["port"], "mode": "bogus"})
    call("settings proxy rejects bad port", "PUT", "/api/settings/proxy",
         expect=(400, 422), json={"host": proxy_before["host"], "port": 70000,
                                  "mode": proxy_before.get("mode", "regular")})
    call("settings proxy accepts current values", "PUT", "/api/settings/proxy",
         json=proxy_before)
    time.sleep(2)
    after = client.get(BASE + "/health")
    proxy_state = after.json().get("proxy", {})
    record("proxy alive after settings restart",
           after.status_code == 200 and proxy_state.get("alive") is True,
           f"{after.status_code} {proxy_state}")

    # ── TLS decryption toggle ─────────────────────────────────────────────
    call("tls toggle off", "POST", "/api/mitm/tls", json={"active": False})
    off = client.get(BASE + "/api/proxy/capture").json()
    record("tls decryption off", off.get("tls_mitm") is False, str(off))
    call("tls toggle on", "POST", "/api/mitm/tls", json={"active": True})
    on = client.get(BASE + "/api/proxy/capture").json()
    record("tls decryption on", on.get("tls_mitm") is True, str(on))
    call("tls restore", "POST", "/api/mitm/tls",
         json={"active": bool(capture_before.get("tls_mitm", True))})

    # ── QUIC / UDP policy ────────────────────────────────────────────────
    # No HTTP surface in this branch: QUIC blocking is configured by the MITM
    # start payload and reported as counters in /api/mitm/status, so there is
    # nothing to PUT here. Checking removed routes only produced 405s that
    # looked like regressions.

    # ── LAN discovery ─────────────────────────────────────────────────────
    devices = call("scan network", "GET", "/api/mitm/scan-network")
    record("scan network found devices", isinstance(devices, list) and len(devices) >= 1,
           f"{len(devices) if isinstance(devices, list) else devices} devices")

    # ── MITM start / stop (ARP only, no rogue DHCP on this LAN) ───────────
    start_response = client.post(BASE + "/api/mitm/start", json={
        "target_ips": [PROBE_TARGET], "spoof_method": "arp",
        "enable_dns_spoof": False, "enable_wifi_ap": False,
    })
    try:
        started = start_response.json()
    except ValueError:
        started = start_response.text[:300]
    if not elevated and start_response.status_code == 400:
        # The correct behaviour without Administrator: refuse with an
        # explanation instead of redirecting the target into a blackhole.
        record("mitm start refuses without admin",
               "administrator" in str(started).lower(),
               str(started)[:240])
        started = None
    else:
        record("mitm start", start_response.status_code == 200,
               f"{start_response.status_code} {str(started)[:200]}")
    if isinstance(started, dict) and started.get("status") == "ok":
        record("mitm reports admin mode", started.get("admin_mode") is True,
               str(started)[:200])
        live = client.get(BASE + "/api/mitm/status").json()
        record("mitm active", live.get("active") is True, str(live)[:200])
        call("mitm stop", "POST", "/api/mitm/stop")
        stopped = client.get(BASE + "/api/mitm/status").json()
        record("mitm inactive after stop", stopped.get("active") is False,
               str(stopped)[:200])
        # Start switches the proxy to transparent and stop leaves it there;
        # put back the mode the app had before the test.
        call("proxy settings restored after mitm", "PUT", "/api/settings/proxy",
             json=proxy_before)
        time.sleep(1)
        restored_health = client.get(BASE + "/health").json().get("proxy", {})
        record("proxy alive after mitm restore", restored_health.get("alive") is True,
               str(restored_health))
    else:
        # Without admin the refusal above is the pass; a failure here would
        # only be a real regression in an elevated run.
        if elevated:
            record("mitm started", False, str(started)[:200])

    # ── CA certificate download / trust state / verified removal ──────────
    # The CA belongs on the target; this PC must end up with no trust left.
    pem = client.get(BASE + "/api/ca-certificate")
    record("ca certificate downloadable",
           pem.status_code == 200 and "BEGIN CERTIFICATE" in pem.text,
           str(pem.status_code))
    state_before = call("ca trust status", "GET", "/api/ca/status")
    removed = call("ca remove (verified)", "POST", "/api/ca/remove")
    record("ca removal verified",
           isinstance(removed, dict) and removed.get("removed") is True,
           str(removed)[:240])
    state_after = client.get(BASE + "/api/ca/status").json()
    record("ca not trusted on this PC afterwards",
           state_after.get("trusted") is False,
           f"before={state_before} after={state_after}")

    # Packet capture (pcap) has no router in this branch: the traffic that
    # matters is captured by the proxy itself, so there is nothing to start.

    # ── exports / backup ──────────────────────────────────────────────────
    for name, path in [
        ("export findings", f"/api/export/findings?session_id={OUTSIDE_SESSION}"),
        ("export requests har", f"/api/requests/export/har?session_id={OUTSIDE_SESSION}"),
        ("backup", "/api/backup"),
    ]:
        response = client.get(BASE + path)
        record(name, response.status_code < 500,
               f"{response.status_code} {len(response.content)} bytes")

    # ── graceful shutdown (last: it stops the backend) ────────────────────
    shutdown = client.post(BASE + "/api/shutdown")
    record("shutdown accepted", shutdown.status_code in (200, 202, 204),
           f"{shutdown.status_code} {shutdown.text[:120]}")
    closed = False
    for _ in range(30):
        time.sleep(0.5)
        try:
            client.get(BASE + "/health", timeout=2)
        except Exception:  # noqa: BLE001
            closed = True
            break
    record("backend exited cleanly", closed, "port closed" if closed else "still listening")

    failed = [c for c in checks if not c[1]]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    for name, _, detail in failed:
        print("  FAILED:", name, "—", detail[:200])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

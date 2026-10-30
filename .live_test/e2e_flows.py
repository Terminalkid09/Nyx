"""End-to-end exercise of the Nyx desktop flows against the local backend.

Every call goes through the HTTP API the Electron renderer uses. Traffic is
sent to the deliberately vulnerable target on 127.0.0.1:8099 (either directly
or through the Nyx proxy on 8080).
"""
import os
import socket
import sys
import time
import uuid

import httpx

BASE = os.environ.get("NYX_BASE", "http://127.0.0.1:8000")
TARGET = os.environ.get("NYX_TARGET", "http://127.0.0.1:8099")


def _lan_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


# The proxy addon treats loopback traffic as Nyx's own and drops it, so the
# capture flow has to talk to the target over the LAN address instead.
LAN = os.environ.get("NYX_LAN", _lan_ip())
TARGET_LAN = f"http://{LAN}:8099"
PROXY = os.environ.get("NYX_PROXY", f"http://{LAN}:8080")

client = httpx.Client(timeout=90)
checks: list[tuple[str, bool, str]] = []
# Unique per run: the passive scanner dedupes repeated (session, url) pairs, so
# a fixed URL would stop producing findings on the second run.
RUN = uuid.uuid4().hex[:8]


def record(name: str, ok: bool, detail: str) -> None:
    checks.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + " — " + detail[:300])


def call(name: str, method: str, path: str, expect=(200,), **kwargs):
    try:
        response = client.request(method, BASE + path, **kwargs)
    except Exception as exc:  # noqa: BLE001
        record(name, False, f"EXC {exc}")
        return None
    ok = response.status_code in expect and response.status_code < 500
    if not ok:
        record(name, False, f"{response.status_code} {response.text[:200]}")
        return None
    body = None
    if response.content:
        try:
            body = response.json()
        except ValueError:
            body = response.text
    return body if ok else None


def get(path: str, **kwargs):
    return call("GET " + path, "GET", path, **kwargs)


def wait_job(path: str, done=("done", "completed", "finished", "cancelled", "failed"), tries=40):
    job = {}
    for _ in range(tries):
        time.sleep(0.5)
        job = client.get(BASE + path).json()
        status = str(job.get("status", "")).lower()
        if status in done:
            return job
    return job


def main() -> int:
    health = client.get(BASE + "/health")
    record("health", health.status_code == 200, str(health.status_code))
    target = client.get(TARGET + "/")
    record("target reachable", target.status_code == 200, str(target.status_code))

    session = call("session create", "POST", "/api/sessions", (200, 201),
                   json={"name": "e2e-" + uuid.uuid4().hex[:6]})
    if not session:
        return 1
    sid = session["id"]

    # --- scope / RoE -----------------------------------------------------
    call("scope rule", "POST", "/api/scope/", (200, 201),
         json={"session_id": sid, "name": "local", "rule_type": "include",
               "pattern": "127.0.0.1", "is_regex": False, "enabled": True})
    check = call("scope check", "POST", "/api/scope/check", json={"session_id": sid, "url": TARGET + "/"})
    record("scope allows target", bool(check and check.get("in_scope")), str(check))
    roe = call("roe create", "POST", "/api/roe", (200, 201),
               json={"name": "e2e", "targets": ["127.0.0.1"], "max_rps": 0})
    if roe:
        call("roe activate", "POST", f"/api/roe/{roe['id']}/activate", (200, 201, 204))
        call("roe verify", "POST", f"/api/roe/{roe['id']}/verify", (200, 201))

    # --- proxy capture ---------------------------------------------------
    # /api/interceptor/toggle flips the flag (the UI relies on that), so only
    # call it when enabled — otherwise every proxied flow is paused and the
    # client times out waiting for a forward.
    was_intercepting = client.get(BASE + "/api/interceptor/status").json().get("enabled")
    if was_intercepting:
        call("interceptor off", "POST", "/api/interceptor/toggle")
    call("proxy capture on", "POST", "/api/proxy/capture", json={"active": True})
    call("proxy session", "PATCH", "/api/proxy/session", json={"session_id": sid})
    try:
        through = httpx.get(TARGET_LAN + "/.env?e2e=" + RUN, proxy=PROXY, timeout=20)
        record("request through proxy", through.status_code == 200 and "DB_PASSWORD" in through.text,
               str(through.status_code))
    except Exception as exc:  # noqa: BLE001
        record("request through proxy", False, f"EXC {exc}")

    # --- passive findings ------------------------------------------------
    time.sleep(3)
    requests = get(f"/api/requests?session_id={sid}&per_page=50")
    record("captured request stored", bool(requests and requests.get("total", 0) >= 1),
           f"total={requests and requests.get('total')}")
    findings = get(f"/api/findings?session_id={sid}&per_page=50")
    modules = sorted({f.get("module") for f in (findings or {}).get("items", [])})
    record("passive findings produced", bool(findings and findings.get("total", 0) >= 1),
           f"total={findings and findings.get('total')} modules={modules}")
    call("capture off", "POST", "/api/proxy/capture", json={"active": False})
    if was_intercepting:
        call("interceptor on", "POST", "/api/interceptor/toggle")

    # --- active scanner --------------------------------------------------
    active = call("active scan run", "POST", "/api/active-scanner/run",
                  json={"base_request": {"method": "GET",
                                         "url": TARGET + "/sqli?id=1",
                                         "headers": {"Host": "127.0.0.1:8099"},
                                         "body": None},
                        "target_params": ["id"],
                        "checks": ["sqli", "xss"],
                        "session_id": sid})
    if active is not None:
        record("active scan returned", active.get("total", 0) >= 1,
               f"results={len(active.get('results') or [])}")
        time.sleep(1)
        after = client.get(f"{BASE}/api/findings?session_id={sid}&per_page=100").json()
        record("active findings persisted", after.get("total", 0) > (findings or {}).get("total", 0),
               f"total={after.get('total')}")

    # --- repeater / custom scanner --------------------------------------
    # session_id is mandatory: Repeater sends real requests, so it is gated by
    # the engagement's scope and the RoE like every other active endpoint.
    repeater = call("repeater send", "POST", "/api/repeater/send",
                    json={"method": "GET", "url": TARGET + "/?q=1", "headers": {},
                          "body": None, "session_id": sid})
    record("repeater got response", bool(repeater and repeater.get("status") == 200),
           str(repeater and repeater.get("status")))

    check_rule = call("custom check create", "POST", "/api/scanner/custom/", (200, 201),
                      json={"name": "e2e-secret", "match_type": "response_body",
                            "match_pattern": "DB_PASSWORD", "is_regex": False,
                            "severity": "high", "description": "e2e"})
    custom = call("custom scanner run", "POST", "/api/scanner/custom/run",
                  json={"url": TARGET + "/.env",
                        "response_body": "DB_PASSWORD=supersecret\nAWS_KEY=AKIAEXAMPLE\n",
                        "response_headers": {"Content-Type": "text/plain"}})
    triggered = [c for c in (custom or []) if c.get("triggered")] if isinstance(custom, list) else []
    record("custom scanner matched", bool(triggered), f"triggered={[c.get('check_name') for c in triggered]}")
    if check_rule:
        call("custom check delete", "DELETE", f"/api/scanner/custom/{check_rule['id']}", (200, 204))

    # --- crawler ---------------------------------------------------------
    crawl = call("crawler start", "POST", "/api/crawler/start", (200, 201, 202),
                 json={"start_url": TARGET + "/", "max_depth": 2, "max_pages": 5,
                       "respect_robots_txt": False, "session_id": sid})
    if crawl:
        job_id = crawl.get("job_id") or crawl.get("id")
        if job_id:
            job = wait_job(f"/api/crawler/status/{job_id}")
            record("crawler finished", str(job.get("status", "")).lower() in ("done", "completed", "finished"),
                   f"status={job.get('status')} pages={job.get('pages_found', job.get('pages_crawled'))}")

    # --- content discovery ----------------------------------------------
    discovery = call("content discovery start", "POST", "/api/content-discovery/start", (200, 201, 202),
                     json={"target_url": TARGET + "/", "wordlist_path": "content_discovery.txt",
                           "session_id": sid, "concurrency": 8})
    if discovery:
        job_id = discovery.get("job_id") or discovery.get("id")
        if job_id:
            job = wait_job(f"/api/content-discovery/status/{job_id}")
            record("content discovery finished", str(job.get("status", "")).lower() in ("done", "completed", "finished"),
                   f"status={job.get('status')} found={job.get('found_count', job.get('results'))}")

    # --- auth scan -------------------------------------------------------
    profile = call("auth profile create", "POST", "/api/auth/profiles", (200, 201),
                   json={"name": "e2e", "target_url": TARGET + "/", "login_url": TARGET + "/",
                         "login_method": "POST", "login_credentials": {"username": "u", "password": "p"},
                         "session_indicator": "session"})
    if profile:
        scan = call("auth scan", "POST", "/api/auth/scan",
                    json={"profile_id": profile.get("id"), "target_url": TARGET + "/", "session_id": sid})
        record("auth scan executed", scan is not None, str(scan)[:160])

    # --- fuzzer ----------------------------------------------------------
    fuzz = call("fuzzer job create", "POST", "/api/fuzzer/jobs", (200, 201),
                json={"session_id": sid,
                      "base_request_id": "00000000-0000-0000-0000-000000000010",
                      "request_template": "GET /?q=§x§ HTTP/1.1\r\nHost: 127.0.0.1:8099\r\n\r\n",
                      "attack_type": "sniper",
                      "positions": [{"name": "x", "wordlist_path": "sqli.txt"}],
                      "grep_matches": [], "extractors": [], "rate_limit_rps": 0})
    if fuzz:
        job = wait_job(f"/api/fuzzer/jobs/{fuzz['id']}")
        results = client.get(f"{BASE}/api/fuzzer/jobs/{fuzz['id']}/results").json()
        codes = sorted({r.get("status") for r in results if r.get("status")})
        record("fuzzer completed", job.get("status") == "done" and codes == [200],
               f"status={job.get('status')} n={len(results)} codes={codes}")

    # --- decoder / comparer / organizer ---------------------------------
    hashed = call("decoder hash", "POST", "/api/decoder/hash", json={"input": "abc", "algorithm": "md5"})
    record("decoder hash value", bool(hashed and "900150983cd24fb0d6963f7d28e17f72" in str(hashed)), str(hashed)[:120])

    comparer = call("comparer create", "POST", "/api/comparer/items", (200, 201),
                    json={"session_id": sid, "left_content": "HTTP/1.1 200 OK\r\n\r\nhello",
                          "right_content": "HTTP/1.1 500 OK\r\n\r\nhello!", "left_label": "a", "right_label": "b"})
    if comparer:
        diff = call("comparer compare", "GET", f"/api/comparer/compare/{comparer['id']}")
        record("comparer diff computed", diff is not None, str(diff)[:160])

    organizer = call("organizer create", "POST", "/api/organizer/", (200, 201),
                     json={"session_id": sid, "title": "e2e", "notes": "note", "tags": ["t"]})
    record("organizer stored", organizer is not None, str(organizer)[:120])

    # --- interceptor / match-replace ------------------------------------
    rule = call("interceptor rule", "POST", "/api/interceptor/rules", (200, 201),
                json={"session_id": sid, "name": "e2e", "scope": "request",
                      "intercept_on_match": False,
                      "match_type": "contains", "match_pattern": "test"})
    if rule:
        call("interceptor rule toggle", "PUT", f"/api/interceptor/rules/{rule.get('id')}",
             json={"enabled": False})

    mrule = call("match-replace rule", "POST", "/api/match-replace/", (200, 201),
                 json={"session_id": sid, "name": "e2e", "scope": "request",
                       "match_type": "contains", "match_pattern": "test", "replacement": "x"})
    if mrule:
        call("match-replace test", "PUT", f"/api/match-replace/{mrule.get('id')}/test",
             json={"input_text": "a test value"})
        call("match-replace toggle", "PATCH", f"/api/match-replace/{mrule.get('id')}/toggle")

    # --- live audit ------------------------------------------------------
    start = call("live audit start", "POST", "/api/live-audit/start", (200, 201, 202))
    if start is not None:
        call("live audit status", "GET", "/api/live-audit/status")
        call("live audit stop", "POST", "/api/live-audit/stop", (200, 201, 204))

    # --- automations / reports ------------------------------------------
    schedule = call("schedule create", "POST", "/api/automations/schedules", (200, 201),
                    json={"name": "e2e", "target_url": TARGET + "/", "cron": "0 3 * * *", "enabled": False})
    call("automations report", "POST", "/api/automations/reports/generate", (200, 201),
         json={"session_id": sid, "scan_name": "e2e"})
    call("report generate", "POST", f"/api/reports/generate?session_id={sid}", (200, 201, 202))

    # --- project / pipeline ---------------------------------------------
    project = call("project create", "POST", "/api/projects", (200, 201),
                   json={"name": "e2e", "description": "test"})
    if project:
        call("project export", "POST", f"/api/projects/{project['id']}/export")
    pipeline = call("pipeline start", "POST", "/api/pipeline/start", (200, 201, 202),
                    json={"target_url": TARGET + "/", "session_id": sid, "config": {"max_depth": 1}})
    if pipeline:
        pid = pipeline.get("pipeline_id") or pipeline.get("id")
        if pid:
            wait_job(f"/api/pipeline/{pid}", done=("done", "completed", "failed", "cancelled"))

    # --- misc UI reads ---------------------------------------------------
    get(f"/api/dashboard/stats?session_id={sid}")
    get("/api/recommendations?limit=10")
    get(f"/api/triage/stats?session_id={sid}")
    get("/api/compliance/owasp")
    get("/metrics")
    get(f"/api/attack-path/{sid}")
    get("/api/settings/")
    get("/api/ws/messages")

    # --- sequencer / auto-exploit ---------------------------------------
    tokens = [str(uuid.uuid4().hex) for _ in range(120)]
    call("sequencer analyze", "POST", "/api/sequencer/analyze", json={"tokens": tokens})
    call("auto-exploit analyze", "POST", "/api/auto-exploit/analyze", json={"url": TARGET + "/sqli?id=1"})
    call("auto-exploit generate", "POST", "/api/auto-exploit/generate", (200, 201),
         json={"findings": [{"title": "SQLi", "type": "sqli", "url": TARGET + "/sqli?id=1",
                             "severity": "high"}]})

    # --- cleanup of test-created records ---------------------------------
    if rule:
        client.delete(f"{BASE}/api/interceptor/rules/{rule['id']}")
    if mrule:
        client.delete(f"{BASE}/api/match-replace/{mrule['id']}")
    if comparer:
        client.delete(f"{BASE}/api/comparer/items/{comparer['id']}")
    if organizer:
        client.delete(f"{BASE}/api/organizer/{organizer['id']}")
    if schedule:
        client.delete(f"{BASE}/api/automations/schedules/{schedule['id']}")

    failed = [c for c in checks if not c[1]]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    for name, _, detail in failed:
        print("  FAILED:", name, "—", detail[:200])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

"""Schema-driven exercise of the safe write endpoints.

Builds a minimal valid body for each POST/PUT/PATCH from /openapi.json and
reports anything that answers 5xx. Endpoints that touch the host network,
certificates, or long-running scans are skipped.
"""
import os
import sys
import uuid

import httpx

BASE = os.environ.get("NYX_BASE", "http://127.0.0.1:8000")
ZERO = "00000000-0000-0000-0000-000000000001"
SESSION = str(uuid.uuid4())

SKIP_PREFIXES = (
    "/api/mitm/start", "/api/mitm/stop", "/api/mitm/tls", "/api/mitm/quic",
    "/api/mitm/udp", "/api/mitm/scan-network",
    "/api/network/capture", "/api/proxy/capture", "/api/ca/remove",
    "/api/backup", "/api/export", "/api/requests/export",
    "/api/fuzzer/jobs", "/api/crawler/start", "/api/pipeline/start",
    "/api/auth/jwt/brute", "/api/auth/jwt/crack",
    "/api/auto-exploit/execute", "/api/auto-exploit/generate",
    "/api/automations/webhooks/test", "/api/proxy-config/test",
    "/api/live-audit/start", "/api/live-audit/stop",
    "/api/repeater/send", "/api/repeater/tabs",
    "/api/scanner/custom/run", "/api/automations/param-discovery",
    "/api/session/macros/run", "/api/sessions", "/api/shutdown",
    "/api/interceptor/forward", "/api/interceptor/drop",
    # Restarts the proxy engine (system proxy / IP forwarding / WinDivert).
    # Calling it mid-sweep left the host without a proxy listener.
    "/api/settings/proxy",
    "/api/auth/scan", "/api/active-scanner/run",
    "/api/content-discovery/start", "/api/content-discovery/stop",
)


def resolve(spec, node):
    if isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"].lstrip("#/").split("/")
        target = spec
        for part in ref:
            target = target[part]
        return resolve(spec, target)
    return node


def sample(spec, schema, name=""):
    schema = resolve(spec, schema or {})
    if "anyOf" in schema:
        schema = resolve(spec, schema["anyOf"][0])
    if "oneOf" in schema:
        schema = resolve(spec, schema["oneOf"][0])
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        return {
            key: sample(spec, value, key)
            for key, value in (schema.get("properties") or {}).items()
            if key in (schema.get("required") or [])
        }
    if kind == "array":
        return []
    if kind == "integer":
        return 1
    if kind == "number":
        return 1.0
    if kind == "boolean":
        return False
    if schema.get("format") == "uuid":
        return SESSION
    if name in ("url", "target_url", "start_url", "login_url"):
        return "http://127.0.0.1:8099/"
    if name in ("name", "title"):
        return "sweep"
    return "x"


def placeholder(path):
    for token, value in {
        "session_id": SESSION, "job_id": ZERO, "profile_id": ZERO,
        "rule_id": ZERO, "finding_id": ZERO, "check_id": ZERO,
        "policy_id": ZERO, "project_id": ZERO, "proxy_id": ZERO,
        "item_id": ZERO, "config_id": ZERO, "tab_id": ZERO, "msg_id": ZERO,
        "cookie_id": ZERO, "schedule_id": ZERO, "template_id": ZERO,
        "webhook_id": ZERO, "pipeline_id": ZERO, "name": "content_discovery.txt",
        "filename": "nope.json", "seq": "1", "stream_id": "1",
        "request_id": ZERO,
    }.items():
        path = path.replace("{" + token + "}", value)
    return path


def main():
    client = httpx.Client(timeout=25)
    spec = client.get(f"{BASE}/openapi.json").json()
    client.post(f"{BASE}/api/sessions", json={"name": "write-sweep"})

    counts = {}
    failures = []
    for path, ops in sorted(spec["paths"].items()):
        if path.startswith(SKIP_PREFIXES):
            continue
        for method in ("post", "put", "patch"):
            if method not in ops:
                continue
            operation = ops[method]
            body_schema = (
                operation.get("requestBody", {})
                .get("content", {})
                .get("application/json", {})
                .get("schema")
            )
            payload = sample(spec, body_schema) if body_schema else None
            url = BASE + placeholder(path)
            try:
                response = client.request(method.upper(), url, json=payload)
            except Exception as exc:  # noqa: BLE001
                failures.append((method.upper(), path, "EXC", str(exc)[:120]))
                continue
            counts[response.status_code] = counts.get(response.status_code, 0) + 1
            if os.environ.get("NYX_VERBOSE") and 400 <= response.status_code < 500:
                print(f"  {response.status_code} {method.upper()} {path} {response.text[:110]}")
            if response.status_code >= 500:
                failures.append(
                    (method.upper(), path, response.status_code, response.text[:160])
                )

    print("write status distribution:", dict(sorted(counts.items())))
    if failures:
        print(f"\nFAILURES ({len(failures)}):")
        for item in failures:
            print(" ", item)
    else:
        print("no 5xx across write endpoints")

    client.close()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

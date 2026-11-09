"""Build the Nyx API coverage matrix.

For every route registered in the running backend:
  * which router module owns it,
  * whether any backend/root test references it,
  * what the live backend answers for a safe GET (or OPTIONS for other verbs).

Writes docs/NYX_TEST_MATRIX.md. Endpoints that change the host (certificates,
capture, MITM, exports, shutdown) are never called.
"""
import json
import os
import re
import pathlib
import sys

import httpx

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = os.environ.get("NYX_BASE", "http://127.0.0.1:8000")
ZERO = "00000000-0000-0000-0000-000000000001"

# Never hit these live: they alter network state, certificates or export data.
UNSAFE = (
    "/api/shutdown", "/api/ca", "/api/mitm/start", "/api/mitm/stop", "/api/mitm/tls",
    "/api/mitm/quic", "/api/mitm/udp", "/api/mitm/scan-network", "/api/network/capture",
    "/api/proxy/capture", "/api/backup", "/api/export", "/api/requests/export",
    "/api/network/export", "/api/settings/proxy", "/api/collaborator/start",
    "/api/collaborator/stop", "/api/auth/jwt/brute", "/api/auth/jwt/crack",
)


def route_modules() -> dict[str, str]:
    """prefix -> module name, read from the route files."""
    out = {}
    for path in (ROOT / "backend" / "api" / "routes").glob("*.py"):
        src = path.read_text(encoding="utf-8", errors="replace")
        match = re.search(r'APIRouter\(prefix="([^"]+)"', src)
        if match:
            out[match.group(1)] = path.stem
    return out


def owner(path: str, prefixes: dict[str, str]) -> str:
    best, best_len = "(main.py)", 0
    for prefix, module in prefixes.items():
        if (path == prefix or path.startswith(prefix + "/")) and len(prefix) > best_len:
            best, best_len = module, len(prefix)
    return best


def test_index() -> str:
    chunks = []
    for folder in ("backend/tests", "tests"):
        for path in (ROOT / folder).glob("*.py"):
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def referenced(route: str, tests: str, module: str) -> bool:
    # Covered = a test references the router prefix or the literal path. The
    # module name alone is not enough: importing a module does not exercise
    # its HTTP surface.
    stem = route.split("{")[0].rstrip("/")
    if stem and stem in tests:
        return True
    return bool(re.search(rf'["\']{re.escape(stem or route)}', tests))


def concretize(path: str) -> str:
    out = re.sub(r"\{[^}]+\}", ZERO, path)
    return out.replace("{seq}", "1").replace("{stream_id}", "1").replace("{filename}", "nope.json")


def probe(client: httpx.Client, method: str, path: str) -> tuple[int | None, str]:
    if any(path.startswith(prefix) for prefix in UNSAFE):
        return None, "skipped (unsafe)"
    url = BASE + concretize(path)
    print(f"  -> {method} {path}", flush=True)
    try:
        if method == "GET":
            response = client.get(url, timeout=8)
        else:
            response = client.request("OPTIONS", url, timeout=8)
    except Exception as exc:  # noqa: BLE001
        return None, f"EXC {type(exc).__name__}"
    note = ""
    if response.status_code >= 500:
        note = response.text[:120].replace("\n", " ")
    return response.status_code, note


def _healthy() -> bool:
    try:
        return httpx.get(f"{BASE}/health", timeout=3).status_code == 200
    except Exception:  # noqa: BLE001
        return False


def _write(rows, prefixes) -> int:
    total = len(rows)
    with_test = sum(1 for r in rows if r["test"] == "sì")
    server_errors = [r for r in rows if r["live"].startswith("5")]
    dead = [r for r in rows if r["live"] == "DEAD"]
    lines = [
        "# Nyx — matrice di copertura API",
        "",
        f"Generata da `.live_test/build_matrix.py` contro `{BASE}`.",
        "",
        f"- Operazioni registrate e sondate: **{total}**",
        f"- Con almeno un riferimento nei test: **{with_test}** ({with_test * 100 // max(total, 1)}%)",
        f"- Risposte 5xx dal live: **{len(server_errors)}**",
        f"- Backend caduto durante lo sweep: **{'sì dopo ' + dead[-1]['method'] + ' ' + dead[-1]['path'] if dead else 'no'}**",
        "",
        "Colonna `live`: `GET` reale per gli endpoint di lettura, `OPTIONS` per gli altri "
        "(nessun effetto collaterale). Gli endpoint che cambiano lo stato della macchina "
        "sono marcati `skip`.",
        "",
    ]
    if server_errors:
        lines += ["## ⚠️ 5xx osservati", ""]
        lines += [f"- `{r['method']} {r['path']}` → {r['live']} — {r['note']}" for r in server_errors]
        lines.append("")

    lines += ["## Dettaglio per router", ""]
    by_module: dict[str, list[dict]] = {}
    for row in rows:
        by_module.setdefault(row["module"], []).append(row)
    for module in sorted(by_module):
        entries = by_module[module]
        no_tests = [e for e in entries if e["test"] == "no"]
        lines.append(f"### `{module}` — {len(entries)} operazioni, {len(no_tests)} senza test")
        lines.append("")
        lines.append("| Metodo | Path | Test | Live |")
        lines.append("|---|---|---|---|")
        for entry in entries:
            live = entry["live"] + (f" — {entry['note']}" if entry["note"] else "")
            lines.append(f"| {entry['method']} | `{entry['path']}` | {entry['test']} | {live} |")
        lines.append("")

    out = ROOT / "docs" / "NYX_TEST_MATRIX.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"ops={total} with_tests={with_test} 5xx={len(server_errors)} dead={len(dead)} -> {out}")
    empty = sorted(m for m, e in by_module.items() if all(x["test"] == "no" for x in e))
    print("routers with no test references:", len(empty))
    print(", ".join(empty))
    return 0


def main() -> int:
    prefixes = route_modules()
    tests = test_index()
    spec = httpx.get(f"{BASE}/openapi.json", timeout=20).json()
    rows = []
    with httpx.Client() as client:
        for path, methods in sorted(spec["paths"].items()):
            if not path.startswith("/api/"):
                continue
            module = owner(path, prefixes)
            http_methods = sorted(m.upper() for m in methods)
            for method in http_methods:
                status, note = probe(client, method, path)
                if status is None and note.startswith("EXC"):
                    # The backend died mid-sweep: record it and stop, so the
                    # crash is attributed to the endpoint we just called.
                    alive = httpx.get(f"{BASE}/health", timeout=3).status_code if _healthy() else None
                    if alive != 200:
                        print(f"BACKEND DEAD after {method} {path}", flush=True)
                        rows.append({"path": path, "method": method, "module": module,
                                     "test": "sì" if referenced(path, tests, module) else "no",
                                     "live": "DEAD", "note": "backend unreachable"})
                        return _write(rows, prefixes)
                rows.append({
                    "path": path, "method": method, "module": module,
                    "test": "sì" if referenced(path, tests, module) else "no",
                    "live": "skip" if status is None else str(status),
                    "note": note,
                })

    return _write(rows, prefixes)


if __name__ == "__main__":
    sys.exit(main())

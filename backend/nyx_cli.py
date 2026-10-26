"""Nyx headless CLI (F-02).

Designed for CI: run the active checks against one URL, write a JSON report and
exit non-zero when a finding meets the ``--fail-on`` threshold.

Usage (from ``backend/``)::

    python nyx_cli.py scan --url https://target.example/ --fail-on high \
        --out nyx-report.json

Exit codes: 0 = clean at/above threshold, 1 = threshold met, 2 = error.
"""
import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def severity_at_least(value: str, threshold: str) -> bool:
    """True when ``value`` is at least as severe as ``threshold``."""
    try:
        return SEVERITY_ORDER.index(value) >= SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False


def build_base_request(url: str, method: str = "GET", headers=None, body: str | None = None) -> dict:
    merged = {"User-Agent": "Nyx-CLI/1.1"}
    for raw in headers or []:
        key, _, value = raw.partition(":")
        if key.strip():
            merged[key.strip()] = value.strip()
    return {
        "method": method.upper(),
        "url": url,
        "headers": merged,
        "body": body,
    }


def extract_params(url: str, body: str | None = None) -> list[str]:
    """Collect testable parameter names from the URL and request body.

    Without ``--params`` the CLI used to test zero parameters (except the
    URL-level checks): a scan of ``/search?q=1`` looked successful while never
    touching ``q``. Extracting is local, cheap and predictable.
    """
    from urllib.parse import parse_qsl, urlparse

    names: list[str] = []

    def add(name: str) -> None:
        name = (name or "").strip()
        if name and name not in names:
            names.append(name)

    for key, _value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        add(key)

    if body:
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, dict):
            for key in parsed:
                add(str(key))
        elif "=" in body:
            for key, _value in parse_qsl(body, keep_blank_values=True):
                add(key)
    return names


def summarise(findings: list[dict], threshold: str) -> dict:
    by_severity = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        level = str(finding.get("severity", "info")).lower()
        if level in by_severity:
            by_severity[level] += 1
    failing = [
        finding for finding in findings
        if severity_at_least(str(finding.get("severity", "info")).lower(), threshold)
    ]
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "fail_on": threshold,
        "failing": len(failing),
        "passed": not failing,
    }


async def _scan(args) -> int:
    # The authorization gate reads RoE profiles from the database, so a CLI run
    # must have the schema even when it never persists a finding.
    from core.storage.database import init_db
    await init_db()

    from modules.scanner.active.scanner import ActiveScanner

    base_request = build_base_request(
        args.url, args.method, args.header, args.body
    )
    scanner = ActiveScanner(event_bus=None)
    if args.checks:
        names = {name.strip() for name in args.checks.split(",") if name.strip()}
        scanner._checks = [
            check for check in scanner.checks
            if check.name in names or any(n in check.name for n in names)
        ]

    params = [p.strip() for p in args.params.split(",") if p.strip()]
    if not params:
        params = extract_params(args.url, args.body)

    try:
        # The scanner honours the deadline per check and returns what finished,
        # so a slow target still produces a usable report instead of nothing.
        results = await scanner.run_checks(
            base_request,
            params,
            event={"session_id": None},
            depth=args.depth,
            deadline_seconds=args.timeout,
        )
    except asyncio.TimeoutError:
        print(f"error: scan exceeded --timeout {args.timeout}s", file=sys.stderr)
        return 2

    # Attach the replay command so a CI consumer can reproduce without the UI.
    from core.storage.evidence import build_curl
    reproduce = build_curl(base_request)
    if reproduce:
        for finding in results:
            finding["reproduce"] = reproduce

    summary = summarise(results, args.fail_on)
    report = {
        "target": args.url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "findings": results,
    }
    payload = json.dumps(report, indent=2, default=str)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(payload)
        print(
            f"{summary['total']} findings ({summary['failing']} at/above "
            f"{args.fail_on}) -> {args.out}"
        )
    else:
        print(payload)

    return 0 if summary["passed"] else 1


def _import_openapi(args) -> int:
    """Turn an OpenAPI document into an inventory without touching the target.

    Nothing is sent, so this runs offline; the exit code reports the contract
    warnings when ``--fail-on`` is given, which is what a CI job wants.
    """
    from modules.importer.openapi import OpenAPIImportError, inventory, parse_document

    try:
        with open(args.path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        document = parse_document(text)
    except OpenAPIImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = inventory(document)
    payload = json.dumps(report, indent=2, default=str)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(payload)

    if args.json:
        print(payload)
    else:
        print(
            f"{report['spec']['title']} {report['spec']['api_version']} "
            f"({report['spec']['version']}): {report['endpoint_count']} operations"
        )
        for method, count in sorted(report["method_counts"].items()):
            print(f"  {method.upper():6} {count}")
        print(f"{len(report['warnings'])} contract warnings")
        for warning in report["warnings"][:20]:
            print(
                f"  {warning['severity']:6} {warning['code']}: {warning['message']}"
            )
        if args.out:
            print(f"inventory -> {args.out}")

    if args.fail_on != "none":
        failing = [
            warning
            for warning in report["warnings"]
            if severity_at_least(warning["severity"], args.fail_on)
        ]
        if failing:
            print(
                f"error: {len(failing)} contract warnings at/above {args.fail_on}",
                file=sys.stderr,
            )
            return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nyx", description="Nyx headless scanner")
    parser.add_argument("--version", action="version", version="Nyx CLI 1.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run active checks against one URL")
    scan.add_argument("--url", required=True, help="absolute target URL")
    scan.add_argument("--method", default="GET")
    scan.add_argument("--header", action="append", default=[], help="'Name: value' (repeatable)")
    scan.add_argument("--body", default=None)
    scan.add_argument(
        "--params", default="",
        help="comma-separated parameters to test (default: extracted from URL/body)",
    )
    scan.add_argument("--checks", default="", help="comma-separated check names (substring match)")
    scan.add_argument("--depth", default="balanced", choices=["fast", "balanced", "deep"])
    scan.add_argument("--timeout", type=float, default=600.0, help="wall-clock scan budget")
    scan.add_argument(
        "--fail-on", default="high",
        choices=SEVERITY_ORDER, help="lowest severity that makes the command exit 1",
    )
    scan.add_argument("--out", default=None, help="write the JSON report here")

    importer = sub.add_parser(
        "import", help="build an endpoint inventory from an API description"
    )
    formats = importer.add_subparsers(dest="format", required=True)
    openapi = formats.add_parser("openapi", help="OpenAPI 2.0 / 3.x, JSON or YAML")
    openapi.add_argument("path", help="path to the document")
    openapi.add_argument("--json", action="store_true", help="print the whole inventory")
    openapi.add_argument("--out", default=None, help="write the inventory JSON here")
    openapi.add_argument(
        "--fail-on",
        default="none",
        choices=["none", *SEVERITY_ORDER],
        help="exit 1 when a contract warning reaches this severity",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        try:
            return asyncio.run(_scan(args))
        except Exception as exc:  # noqa: BLE001 — CLI boundary: report, don't traceback
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.command == "import":
        return _import_openapi(args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())

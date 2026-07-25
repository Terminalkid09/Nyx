from modules.scanner.base_check import BaseCheck, CheckResult

TIMING_HEADERS = [
    "x-runtime",
    "x-response-time",
    "x-timer",
    "server-timing",
    "x-powered-by",
    "x-aspnet-duration",
    "x-fastcgi-time",
    "x-rendertime",
    "x-elapsed",
    "x-process-time",
    "x-execution-time",
    "x-duration",
    "x-request-duration",
    "cf-request-time",
]


class TimingHeadersCheck(BaseCheck):
    name = "timing_headers"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        for header in TIMING_HEADERS:
            val = headers_lower.get(header, "")
            if val:
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title=f"Timing information leaked via '{header}' header",
                    description=f"Response header '{header}: {val}' leaks server-side timing information, "
                                f"which can aid attackers in timing attacks.",
                    evidence=f"{header}: {val}",
                    remediation="Remove timing headers from responses or restrict them to debug environments.",
                    cwe="CWE-200",
                ))

        return results

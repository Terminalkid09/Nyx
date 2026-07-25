import re
from modules.scanner.base_check import BaseCheck, CheckResult

SERVER_LEAK_PATTERNS = [
    (r"nginx/\d+\.\d+\.\d+", "Nginx version exposed"),
    (r"Apache/\d+\.\d+\.\d+", "Apache version exposed"),
    (r"Microsoft-IIS/\d+\.\d+", "IIS version exposed"),
    (r"X-Powered-By:\s*\S+", "X-Powered-By header exposes technology stack"),
    (r"X-AspNet-Version:\s*\S+", "ASP.NET version exposed"),
    (r"Server:\s*\S+", "Server header exposes software information"),
]


class InfoLeakageCheck(BaseCheck):
    name = "info_leakage"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())

        for pattern, title in SERVER_LEAK_PATTERNS:
            match = re.search(pattern, headers_str, re.IGNORECASE)
            if match:
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title=title,
                    description=f"The response header exposes: {match.group(0)}",
                    evidence=match.group(0),
                    remediation="Configure your web server to hide version details and use generic Server headers.",
                    cwe="CWE-200",
                ))

        body = event.get("body", "") or ""
        stacktrace_patterns = [
            r"Traceback \(most recent call last\)",
            r"at\s+\S+\.java:\d+\)",
            r"in\s+\S+\.php on line \d+",
            r"Stack trace:",
            r"#\d+\s+\S+\.py:\d+",
        ]
        for pattern in stacktrace_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Stack trace exposed in response body",
                    description="The response contains a stack trace, revealing internal application structure and code paths.",
                    evidence=f"Matched pattern: {pattern}",
                    remediation="Disable debug mode in production and configure custom error pages.",
                    cwe="CWE-209",
                ))
                break

        return results

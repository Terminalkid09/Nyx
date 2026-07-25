import re
from modules.scanner.base_check import BaseCheck, CheckResult


class InfoInternalIpCheck(BaseCheck):
    name = "info_internal_ip"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        combined = body + "\n".join(f"{k}: {v}" for k, v in headers.items()) if body else "\n".join(f"{k}: {v}" for k, v in headers.items())
        if not combined:
            return results
        private_ip_patterns = [
            (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "RFC 1918 10.x.x.x"),
            (r"\b172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b", "RFC 1918 172.16-31.x.x"),
            (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "RFC 1918 192.168.x.x"),
            (r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "Loopback address"),
            (r"\b169\.254\.\d{1,3}\.\d{1,3}\b", "Link-local address"),
        ]
        for pattern, desc in private_ip_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title=f"Internal IP address disclosed ({desc})",
                    description=f"An internal IP address matching {desc} was found in the response body or headers, revealing network topology.",
                    evidence=f"Pattern: {pattern}\nBody/headers: {combined[:300]}",
                    remediation="Remove internal IP addresses from response bodies and headers. Use generic error messages that do not reveal infrastructure details.",
                    cwe="CWE-200",
                ))
                break
        return results

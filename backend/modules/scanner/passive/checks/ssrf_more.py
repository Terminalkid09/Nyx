import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SsrfMoreCheck(BaseCheck):
    name = "ssrf_more"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = event.get("url", "") or request_data.get("url", "")
        body = event.get("request_body", "") or ""
        combined = f"{url} {body}"

        ssrf_patterns = [
            (r"https?://0x[0-9a-fA-F]+\.", "IPv6 hex-encoded SSRF"),
            (r"https?://0+[0-9]+\.", "Decimal IP SSRF (leading zeros)"),
            (r"https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", "Direct IP SSRF"),
            (r"https?://0x[0-9a-fA-F]+\.[0-9a-fA-F]+", "Hex IP SSRF"),
            (r"https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "IPv4 direct IP SSRF"),
            (r"https?://\[?[0-9a-fA-F:]+\]?", "IPv6 SSRF"),
            (r"https?://[0-9]+\.0\.0\.1", "Decimal IP SSRF (0.0.0.1 variant)"),
            (r"https?://0177\.0\.0\.1", "Octal IP SSRF"),
            (r"https?://2130706433", "Decimal IP SSRF (integer format)"),
            (r"https?://[0-9a-fA-F]{32}\.", "DNS rebinding hex IP"),
        ]
        for pattern, desc in ssrf_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="SSRF variant detected",
                    description=f"{desc} found. SSRF may allow accessing internal resources.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Validate and restrict outbound URLs. Use an allowlist of permitted domains. Block access to internal IP ranges.",
                    cwe="CWE-918",
                ))
                break
        return results

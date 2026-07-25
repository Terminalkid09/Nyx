import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CdnOriginIpCheck(BaseCheck):
    name = "cdn_origin_ip"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        ip_headers = ["x-origin-ip", "x-real-ip", "x-forwarded-for", "x-cluster-client-ip", "x-originating-ip"]
        ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        for hdr in ip_headers:
            val = headers_lower.get(hdr, "")
            if val:
                ips = ip_pattern.findall(val)
                for ip in ips:
                    if not ip.startswith("10.") and not ip.startswith("172.16.") and not ip.startswith("192.168."):
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title=f"CDN bypass via origin IP disclosure: {hdr}",
                            description=f"The '{hdr}' header reveals an IP address '{ip}' which may be the origin server IP, allowing CDN bypass.",
                            evidence=f"Header: {hdr}: {val}\nIP: {ip}",
                            remediation="Remove origin IP disclosure headers. Ensure the CDN hides the origin server IP address.",
                            cwe="CWE-200",
                        ))
        return results

import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


VERSION_PATTERNS = [
    (r"nginx/(\d+\.\d+\.\d+)", "nginx"),
    (r"Apache/(\d+\.\d+\.\d+)", "Apache"),
    (r"Microsoft-IIS/(\d+\.\d+)", "IIS"),
    (r"PHP/(\d+\.\d+\.\d+)", "PHP"),
    (r"OpenSSL/(\d+\.\d+\.\d+)", "OpenSSL"),
    (r"Python/(\d+\.\d+\.\d+)", "Python"),
    (r"Node\.?js/(\d+\.\d+\.\d+)", "Node.js"),
    (r"Express/(\d+\.\d+\.\d+)", "Express"),
    (r"Go-http-client/(\d+\.\d+)", "Go HTTP"),
    (r"Java/(\d+\.\d+(?:_\d+)?)", "Java"),
    (r"Ruby/(\d+\.\d+\.\d+)", "Ruby"),
]


class ActiveVersionEnumCheck(BaseCheck):
    name = "active_version_enum"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            try:
                resp = await client.get(base_request.get("url", ""))
                headers_str = str(dict(resp.headers))
                for pattern, software in VERSION_PATTERNS:
                    m = re.search(pattern, headers_str, re.I)
                    if m:
                        version = m.group(1) if m.lastindex else m.group(0)
                        results.append(CheckResult(
                            triggered=True,
                            severity="low",
                            title=f"Software Version Enumerated: {software} {version}",
                            description=f"{software} version {version} exposed in response headers.",
                            evidence=f"Software: {software}\nVersion: {version}",
                            remediation="Remove or obfuscate version information from server headers.",
                            cwe="CWE-200",
                        ))
            except Exception:
                pass
        return results

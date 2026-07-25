import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


SQLMAP_API_INDICATORS = [
    "sqlmap/",
    "taskid",
    "tasks",
    "admin",
    "/scan/",
    "/option/",
]


class ActiveSqlmapApiCheck(BaseCheck):
    name = "active_sqlmap_api"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            paths = ["/sqlmap", "/sqlmap/", "/api", "/api/"]
            for path in paths:
                try:
                    resp = await client.get(f"{base_url}{path}")
                    text = resp.text.lower()
                    for indicator in SQLMAP_API_INDICATORS:
                        if indicator in text:
                            results.append(CheckResult(
                                triggered=True,
                                severity="critical",
                                title="sqlmap API Exposed",
                                description=f"sqlmap REST API detected at '{path}'.",
                                evidence=f"URL: {base_url}{path}\nIndicator: {indicator}",
                                remediation="Remove sqlmap API from production. Use dedicated security testing infrastructure.",
                                cwe="CWE-200",
                            ))
                            break
                except Exception:
                    continue
        return results

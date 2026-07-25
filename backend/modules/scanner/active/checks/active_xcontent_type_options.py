import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveXcontentTypeOptionsCheck(BaseCheck):
    name = "active_xcontent_type_options"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            try:
                resp = await client.get(url, headers=req.get("headers", {}))
                xcto = resp.headers.get("x-content-type-options", "")
                if xcto.lower() != "nosniff":
                    results.append(CheckResult(
                        triggered=True,
                        severity="low",
                        title="Missing X-Content-Type-Options: nosniff",
                        description="Response is missing the X-Content-Type-Options: nosniff header, allowing MIME type sniffing.",
                        evidence=f"X-Content-Type-Options: {xcto}",
                        remediation="Add X-Content-Type-Options: nosniff header to all responses.",
                        cwe="CWE-693",
                    ))
            except Exception:
                pass
        return results

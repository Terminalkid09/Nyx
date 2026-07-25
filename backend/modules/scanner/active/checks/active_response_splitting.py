import re
import httpx
from urllib.parse import urlparse, quote
from modules.scanner.base_check import BaseCheck, CheckResult

PAYLOADS = ['%0d%0aContent-Length:0%0d%0a%0d%0aInjected', '%0d%0aSet-Cookie:session=injected']


class ActiveResponseSplittingCheck(BaseCheck):
    name = "active_response_splitting"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            for payload in PAYLOADS:
                try:
                    resp = await client.get(f"{base_url}/redirect?url={quote(payload)}", headers=req.get("headers", {}), allow_redirects=False)
                    if resp.status_code in [301, 302] and "Injected" in resp.text:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="HTTP Response Splitting via Redirect",
                            description="CRLF sequences in redirect URLs enable HTTP response splitting, allowing injection of arbitrary responses.",
                            evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                            remediation="Validate and sanitize all redirect URLs. Remove or encode CRLF characters. Use a whitelist of allowed redirect targets.",
                            cwe="CWE-113",
                        ))
                except Exception:
                    continue
        return results

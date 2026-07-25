import httpx
import re
from modules.scanner.base_check import BaseCheck, CheckResult


DOM_XSS_SINKS = [
    (r'\.innerHTML\s*=', "innerHTML assignment"),
    (r'\.outerHTML\s*=', "outerHTML assignment"),
    (r'document\.write\s*\(', "document.write"),
    (r'eval\s*\(', "eval()"),
    (r'setTimeout\s*\(', "setTimeout()"),
    (r'setInterval\s*\(', "setInterval()"),
    (r'new\s+Function\s*\(', "new Function()"),
    (r'\.insertAdjacentHTML\s*\(', "insertAdjacentHTML"),
    (r'srcdoc\s*=', "srcdoc attribute"),
]


class ActiveXssDomBasedCheck(BaseCheck):
    name = "active_xss_dom_based"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            try:
                resp = await client.get(base_request.get("url", ""))
                body = resp.text
                js_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.I | re.DOTALL)
                js_blocks += re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', body, re.I)
                js_text = " ".join(js_blocks)

                for pattern, sink in DOM_XSS_SINKS:
                    if re.search(pattern, js_text):
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title=f"DOM-based XSS Sink Detected: {sink}",
                            description=f"Potential DOM XSS sink '{sink}' found in page JavaScript.",
                            evidence=f"Sink: {sink}",
                            remediation="Avoid using dangerous DOM APIs with user input. Use textContent instead of innerHTML. Sanitize all inputs.",
                            cwe="CWE-79",
                        ))
            except Exception:
                pass
        return results

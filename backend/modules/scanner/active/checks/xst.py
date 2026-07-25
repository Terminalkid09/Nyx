import copy
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class XstCheck(BaseCheck):
    name = "xst"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        modified = copy.deepcopy(base_request)
        modified["method"] = "TRACE"

        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            try:
                resp = await client.request(**modified)
                body = resp.text if resp.text else ""
                method = base_request.get("method", "GET").upper()
                url = base_request.get("url", "")

                if resp.status_code == 200 and body:
                    request_body = base_request.get("content", base_request.get("data", ""))
                    if request_body and request_body in body:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Cross-Site Tracing (XST) vulnerability",
                            description="TRACE method is enabled and echoes back the request body, "
                                        "allowing XST attacks to capture sensitive headers.",
                            evidence=f"Method: TRACE active\n"
                                     f"Request body reflected: '{request_body[:100]}'\n"
                                     f"Response status: {resp.status_code}",
                            remediation="Disable the TRACE method on the web server. "
                                        "Add 'TraceEnable off' in Apache or disable in other server configs.",
                            cwe="CWE-603",
                        ))
                    else:
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title="TRACE method enabled",
                            description="TRACE method is enabled on the server, increasing attack surface.",
                            evidence=f"Method: TRACE\nResponse status: {resp.status_code}\nURL: {url}",
                            remediation="Disable the TRACE method on the web server.",
                            cwe="CWE-603",
                        ))

                allow_header = resp.headers.get("allow", "")
                if "TRACE" in allow_header.upper():
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title="TRACE method advertised in Allow header",
                        description="The Allow header indicates TRACE method is supported.",
                        evidence=f"Allow: {allow_header}",
                        remediation="Remove TRACE from allowed HTTP methods.",
                        cwe="CWE-603",
                    ))

            except Exception:
                pass

        return results

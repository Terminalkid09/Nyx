import copy
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class CsrfActiveCheck(BaseCheck):
    name = "csrf_active"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            original_method = base_request.get("method", "GET").upper()
            if original_method not in ("POST", "PUT", "DELETE", "PATCH"):
                return results

            tests = [
                {
                    "name": "No Origin header",
                    "mod": lambda h: {k: v for k, v in h.items() if k.lower() != "origin"},
                },
                {
                    "name": "No Referer header",
                    "mod": lambda h: {k: v for k, v in h.items() if k.lower() != "referer"},
                },
                {
                    "name": "No Origin and Referer",
                    "mod": lambda h: {k: v for k, v in h.items()
                                      if k.lower() not in ("origin", "referer")},
                },
                {
                    "name": "Changed Content-Type to text/plain",
                    "mod": lambda h: {**h, "Content-Type": "text/plain"},
                },
                {
                    "name": "Arbitrary Origin header",
                    "mod": lambda h: {**h, "Origin": "https://evil.com"},
                },
                {
                    "name": "Custom X-Custom header",
                    "mod": lambda h: {**h, "X-Custom-Header": "test"},
                },
                {
                    "name": "Fake Referer header",
                    "mod": lambda h: {**h, "Referer": "https://evil.com/fake"},
                },
            ]

            for test in tests:
                modified = copy.deepcopy(base_request)
                current_headers = dict(modified.get("headers", {}))
                modified["headers"] = test["mod"](current_headers)
                ref_status = None

                try:
                    resp = await client.request(**modified)
                    ref_status = resp.status_code

                    if resp.status_code in (200, 201, 204, 301, 302, 303):
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title=f"CSRF protection may be insufficient: {test['name']}",
                            description=f"Request with {test['name']} returned status {resp.status_code}, "
                                        f"indicating CSRF protection may not be properly enforced.",
                            evidence=f"Test: {test['name']}\nStatus: {resp.status_code}\nMethod: {original_method}",
                            remediation="Implement CSRF tokens for all state-changing requests. "
                                        "Validate Origin/Referer headers against a whitelist.",
                            cwe="CWE-352",
                        ))
                except Exception:
                    continue

        return results

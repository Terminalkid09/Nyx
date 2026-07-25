import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


VERB_TAMPERING_HEADERS = [
    ("X-HTTP-Method", "GET"),
    ("X-HTTP-Method-Override", "GET"),
    ("X-Method-Override", "GET"),
    ("X-HTTP-Method", "PUT"),
    ("X-HTTP-Method-Override", "DELETE"),
]


class ActiveVerbTamperingCheck(BaseCheck):
    name = "active_verb_tampering"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        url = base_request.get("url", "")

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for header_name, header_value in VERB_TAMPERING_HEADERS:
                try:
                    resp = await client.get(url, headers={header_name: header_value})
                    if resp.status_code not in (405, 400, 403, 501):
                        if resp.status_code in (200, 201, 202, 204, 302, 303):
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title=f"HTTP Verb Tampering via {header_name}",
                                description=f"Endpoint accepted GET with '{header_name}: {header_value}' header.",
                                evidence=f"Header: {header_name}: {header_value}\nStatus: {resp.status_code}",
                                remediation="Do not trust X-HTTP-Method-Override headers. Validate actual HTTP method server-side.",
                                cwe="CWE-749",
                            ))
                except Exception:
                    continue
        return results

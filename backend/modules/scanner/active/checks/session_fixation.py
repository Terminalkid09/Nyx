import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


SESSION_COOKIES = [
    "PHPSESSID=attacker_session_id_12345",
    "JSESSIONID=attacker_session_id_12345",
    "ASP.NET_SessionId=attacker_session_id_12345",
    "session=attacker_session_id_12345",
    "sid=attacker_session_id_12345",
    "token=attacker_session_id_12345",
]


class SessionFixationCheck(BaseCheck):
    name = "active_session_fixation"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for cookie in SESSION_COOKIES:
                modified = self._inject_cookie(base_request, cookie)
                try:
                    resp = await client.request(**modified)
                    set_cookie = resp.headers.get("set-cookie", "") or resp.headers.get("Set-Cookie", "")
                    if resp.status_code == 200 and "attacker_session" not in set_cookie:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Session fixation detected",
                            description=f"Server accepted attacker-controlled session cookie '{cookie}'.",
                            evidence=f"Cookie: {cookie}\nStatus: {resp.status_code}",
                            remediation="Regenerate session IDs after authentication. Do not accept user-supplied session IDs.",
                            cwe="CWE-384",
                        ))
                except Exception:
                    continue
        return results

    def _inject_cookie(self, base: dict, cookie: str) -> dict:
        import copy
        req = copy.deepcopy(base)
        req["headers"] = {**req.get("headers", {}), "Cookie": cookie}
        return req

import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveH2cSmugglingCheck(BaseCheck):
    name = "active_h2c_smuggling"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            try:
                resp = await client.get(
                    base_request.get("url", ""),
                    headers={"Upgrade": "h2c", "Connection": "Upgrade", "HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA"},
                )
                if resp.status_code == 101 and "h2c" in resp.headers.get("upgrade", "").lower():
                    results.append(CheckResult(
                        triggered=True,
                        severity="high",
                        title="HTTP/2 Cleartext (h2c) Smuggling",
                        description="Server supports h2c upgrade, enabling potential request smuggling.",
                        evidence=f"URL: {base_request.get('url', '')}\nStatus: 101 Switching Protocols",
                        remediation="Disable h2c upgrade if not needed. Use HTTP/2 over TLS (h2) only.",
                        cwe="CWE-444",
                    ))
            except Exception:
                pass
        return results

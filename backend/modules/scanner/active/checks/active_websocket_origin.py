import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


class ActiveWebsocketOriginCheck(BaseCheck):
    name = "active_websocket_origin"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            ws_paths = ["/ws", "/websocket", "/socket", "/ws/", "/socket.io/"]
            for path in ws_paths:
                try:
                    resp = await client.get(f"{base_url}{path}", headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Origin": "http://evil.com",
                    })
                    if resp.status_code == 101 or "websocket" in resp.headers.get("upgrade", "").lower():
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="WebSocket Without Origin Validation",
                            description=f"WebSocket endpoint at '{path}' accepted connection from malicious origin.",
                            evidence=f"URL: {base_url}{path}\nOrigin: http://evil.com",
                            remediation="Validate WebSocket Origin header server-side. Implement CSRF tokens for WebSocket connections.",
                            cwe="CWE-1385",
                        ))
                except Exception:
                    continue
        return results

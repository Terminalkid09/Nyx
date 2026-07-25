import re
from modules.scanner.base_check import BaseCheck, CheckResult


class WsCrossOriginCheck(BaseCheck):
    name = "ws_cross_origin"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        ws_pattern = re.compile(r"new\s+WebSocket\s*\(\s*['\"](wss?://[^'\"]+)['\"]", re.IGNORECASE)
        for match in ws_pattern.finditer(body):
            ws_url = match.group(1)
            base_url = request_data.get("url", "") or event.get("url", "")
            if "://" in base_url and "://" in ws_url:
                base_domain = base_url.split("://")[1].split("/")[0].lower()
                ws_domain = ws_url.split("://")[1].split("/")[0].lower()
                if base_domain != ws_domain:
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title="WebSocket cross-origin connection",
                        description=f"Page connects to WebSocket at '{ws_url}' which is a different origin than the page '{base_domain}'. This may be vulnerable to cross-origin WebSocket hijacking.",
                        evidence=f"Page origin: {base_domain}\nWebSocket URL: {ws_url}",
                        remediation="Ensure WebSocket server validates the Origin header. Use authentication tokens in WebSocket handshake.",
                        cwe="CWE-346",
                    ))
                    break
        return results

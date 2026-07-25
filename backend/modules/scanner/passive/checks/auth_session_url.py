import re
from modules.scanner.base_check import BaseCheck, CheckResult


class AuthSessionUrlCheck(BaseCheck):
    name = "auth_session_url"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        if not url:
            return results
        session_params = [
            r"[?&]session\s*=\s*[a-zA-Z0-9%]{10,}",
            r"[?&]sid\s*=\s*[a-zA-Z0-9%]{10,}",
            r"[?&]token\s*=\s*[a-zA-Z0-9%]{10,}",
            r"[?&]auth\s*=\s*[a-zA-Z0-9%]{10,}",
            r"[?&]jsessionid\s*=\s*[a-zA-Z0-9%]{10,}",
            r"[?&]phpsessid\s*=\s*[a-zA-Z0-9%]{10,}",
            r"[?&]aspsessionid\s*=\s*[a-zA-Z0-9%]{10,}",
        ]
        for pattern in session_params:
            if re.search(pattern, url, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Session token in URL",
                    description="Session identifier found in URL query parameters. Session tokens in URLs can be leaked via Referer header, browser history, and server logs.",
                    evidence=f"URL: {url}",
                    remediation="Transmit session tokens via HTTP-only cookies only. Avoid including session identifiers in URLs.",
                    cwe="CWE-598",
                ))
                break
        return results

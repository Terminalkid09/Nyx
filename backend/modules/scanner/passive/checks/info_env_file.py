import re
from modules.scanner.base_check import BaseCheck, CheckResult


class InfoEnvFileCheck(BaseCheck):
    name = "info_env_file"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", ""))
        body = event.get("response_body", "") or event.get("body", "") or ""
        status = event.get("status")
        env_paths = [".env", ".env.local", ".env.production", ".env.development", ".env.example"]
        is_env_path = any(p in path.lower() for p in env_paths)
        if is_env_path and status == 200 and body:
            env_patterns = [
                r"^[A-Z_]+=",
                r"DB_",
                r"SECRET",
                r"PASSWORD",
                r"API_KEY",
                r"TOKEN",
                r"AUTH",
            ]
            is_env_content = any(re.search(p, body, re.MULTILINE) for p in env_patterns)
            if is_env_content:
                results.append(CheckResult(
                    triggered=True,
                    severity="critical",
                    title=".env file exposed",
                    description=f"Environment configuration file is exposed at {path}, revealing sensitive configuration variables.",
                    evidence=f"URL: {path}\nStatus: {status}\nBody snippet: {body[:500]}",
                    remediation="Block access to .env files in production. Store environment variables in server configuration, not in files accessible via the web.",
                    cwe="CWE-200",
                ))
        return results

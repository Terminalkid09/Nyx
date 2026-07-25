import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveGitExposedCheck(BaseCheck):
    name = "active_git_exposed"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        sensitive_paths = [
            "/.git/config",
            "/.git/HEAD",
            "/.gitignore",
            "/.env",
            "/.aws/credentials",
            "/.svn/entries",
            "/.DS_Store",
            "/WEB-INF/web.xml",
            "/.htaccess",
            "/config.php",
            "/wp-config.php.bak",
            "/config.php.old",
            "/database.yml",
            "/appsettings.json",
            "/config.json",
        ]

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for path in sensitive_paths:
                try:
                    resp = await client.get(f"{base_url}{path}")
                    if resp.status_code == 200 and len(resp.content) > 10:
                        if "ref:" in resp.text or "repository" in resp.text.lower() or "[database]" in resp.text or "root" in resp.text:
                            results.append(CheckResult(
                                triggered=True,
                                severity="critical",
                                title="Sensitive File Exposed",
                                description=f"Sensitive file '{path}' is publicly accessible.",
                                evidence=f"URL: {base_url}{path}\nStatus: {resp.status_code}\nSize: {len(resp.content)} bytes",
                                remediation="Remove sensitive files from web root. Block access to .git, .env, .aws, and config files via web server rules.",
                                cwe="CWE-540",
                            ))
                except Exception:
                    continue
        return results

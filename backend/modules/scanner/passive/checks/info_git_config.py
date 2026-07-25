import re
from modules.scanner.base_check import BaseCheck, CheckResult


class InfoGitConfigCheck(BaseCheck):
    name = "info_git_config"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", ""))
        body = event.get("response_body", "") or event.get("body", "") or ""
        status = event.get("status")
        git_paths = [".git/config", ".git/HEAD", ".git/index", ".gitignore", ".gitattributes"]
        is_git_path = any(p in path.lower() for p in git_paths)
        if is_git_path and status == 200:
            if "[core]" in body or "ref:" in body or "repositoryformatversion" in body:
                results.append(CheckResult(
                    triggered=True,
                    severity="critical",
                    title=".git/config exposed",
                    description=f"Git repository configuration file is exposed at {path}, revealing repository structure and potentially credentials.",
                    evidence=f"URL: {path}\nStatus: {status}\nBody snippet: {body[:500]}",
                    remediation="Block access to .git directory and all hidden files in production. Configure the web server to deny access to dotfiles.",
                    cwe="CWE-200",
                ))
        return results

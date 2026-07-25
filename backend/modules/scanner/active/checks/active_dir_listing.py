import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


DIR_LISTING_INDICATORS = [
    "Index of /",
    "[parent directory]",
    "Directory listing for",
    "<title>Index of",
    "Parent Directory</a>",
]


class ActiveDirListingCheck(BaseCheck):
    name = "active_dir_listing"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        common_dirs = ["/", "/admin", "/uploads", "/backup", "/logs", "/images", "/css", "/js", "/assets", "/static", "/media", "/files", "/downloads", "/tmp", "/private", "/config"]

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for directory in common_dirs:
                try:
                    target = f"{base_url}{directory}/"
                    resp = await client.get(target)
                    for indicator in DIR_LISTING_INDICATORS:
                        if indicator.lower() in resp.text.lower() and resp.status_code == 200:
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title="Directory Listing Enabled",
                                description=f"Directory listing is enabled at {directory}",
                                evidence=f"URL: {target}\nIndicator: {indicator}\nStatus: {resp.status_code}",
                                remediation="Disable directory listing in web server config. Use index files or rewrite rules.",
                                cwe="CWE-548",
                            ))
                            break
                except Exception:
                    continue
        return results

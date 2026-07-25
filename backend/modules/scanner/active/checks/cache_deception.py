import copy
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult

DECEPTION_EXTENSIONS = [".css", ".js", ".jsx", ".ts", ".tsx", ".vue", ".map"]


class CacheDeceptionCheck(BaseCheck):
    name = "cache_deception"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for ext in DECEPTION_EXTENSIONS:
                modified = copy.deepcopy(base_request)
                url = modified["url"]
                if "?" in url:
                    base_url = url.split("?")[0]
                    qs = url.split("?")[1]
                    modified["url"] = f"{base_url}{ext}?{qs}"
                else:
                    modified["url"] = f"{url}{ext}"

                try:
                    resp = await client.request(**modified)
                    content_type = (resp.headers.get("content-type") or "").lower()

                    if resp.status_code == 200:
                        if ("text/html" in content_type or "application/json" in content_type):
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title="Cache deception possible",
                                description=f"Appending '{ext}' returned 200 with content-type '{content_type}', "
                                            f"indicating cache deception may be possible.",
                                evidence=f"Extension: {ext}\nURL: {url}{ext}\nContent-Type: {content_type}",
                                remediation="Configure caching to serve dynamic content with proper Cache-Control headers "
                                            "and ensure cache keys are not based solely on file extensions.",
                                cwe="CWE-444",
                            ))
                except Exception:
                    continue

        return results

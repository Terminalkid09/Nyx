from modules.scanner.base_check import BaseCheck, CheckResult


class CachePoisoningCheck(BaseCheck):
    name = "cache_poisoning"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        x_cache = headers_lower.get("x-cache", "")
        if x_cache and x_cache.lower() in ("hit", "miss", "hit from cloudfront", "hit from cloudflare"):
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="Caching header present: X-Cache",
                description="Response includes X-Cache header indicating content is being cached, which could be leveraged for cache poisoning.",
                evidence=f"X-Cache: {x_cache}",
                remediation="Review caching configuration. Ensure cache keys include all relevant request attributes. Implement proper cache partitioning.",
                cwe="CWE-444",
            ))

        age = headers_lower.get("age", "")
        if age and age.isdigit() and int(age) > 0:
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="Cached response via Age header",
                description=f"Response has Age: {age}s, indicating it was served from cache.",
                evidence=f"Age: {age}",
                remediation="Ensure cache invalidation is properly configured for dynamic content.",
                cwe="CWE-444",
            ))

        cdn_headers = ["x-cf-cache-status", "cf-cache-status", "x-served-by",
                       "x-cache-hits", "x-amz-cf-pop", "x-akamai-stored"]
        for cdn_hdr in cdn_headers:
            val = headers_lower.get(cdn_hdr, "")
            if val:
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title=f"CDN caching header: {cdn_hdr}",
                    description=f"Response contains CDN cache header '{cdn_hdr}: {val}', indicating content delivery network caching.",
                    evidence=f"{cdn_hdr}: {val}",
                    remediation="Review CDN cache configuration to prevent cache poisoning attacks.",
                    cwe="CWE-444",
                ))

        content_type = headers_lower.get("content-type", "")
        is_dynamic = any(
            t in content_type for t in ["text/html", "application/json", "application/xml"]
        ) if content_type else True

        cache_control = headers_lower.get("cache-control", "")
        if is_dynamic and "no-store" not in cache_control.lower():
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="Missing Cache-Control: no-store on dynamic content",
                description="Dynamic content response lacks Cache-Control: no-store, which may allow caching of sensitive responses.",
                evidence=f"Cache-Control: {cache_control}",
                remediation="Add 'Cache-Control: no-store' to all dynamic content responses to prevent caching.",
                cwe="CWE-524",
            ))

        return results

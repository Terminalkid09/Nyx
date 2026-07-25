import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CdnMisconfigCheck(BaseCheck):
    name = "cdn_misconfig"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        cdn_headers = {
            "x-cdn": "CDN header",
            "x-edge": "Edge server header",
            "x-amz-cf-id": "CloudFront ID",
            "x-amz-cf-pop": "CloudFront POP",
            "cf-ray": "Cloudflare Ray",
            "x-sucuri-cache": "Sucuri cache",
            "x-akamai-": "Akamai header",
            "x-fastly-": "Fastly header",
        }
        found_misconfigs = []
        for hdr, desc in cdn_headers.items():
            for key in headers_lower:
                if hdr in key:
                    found_misconfigs.append(f"{key}: {headers_lower[key]}")
        if len(found_misconfigs) >= 3:
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="CDN misconfiguration - excessive header exposure",
                description=f"Response exposes {len(found_misconfigs)} CDN-specific headers, which may aid attackers in fingerprinting the CDN configuration.",
                evidence="\n".join(found_misconfigs[:10]),
                remediation="Review CDN configuration to minimize exposed headers. Remove unnecessary debug/informational CDN headers.",
                cwe="CWE-200",
            ))
        return results

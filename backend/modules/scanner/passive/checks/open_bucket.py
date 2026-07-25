import re
from modules.scanner.base_check import BaseCheck, CheckResult


class OpenBucketCheck(BaseCheck):
    name = "open_bucket"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("body", "") or ""
        status = event.get("status")

        patterns = {
            "aws_s3": {
                "pattern": r"https?://[a-zA-Z0-9._-]+\.s3[.\-][a-z0-9\-]+\.amazonaws\.com",
                "title": "AWS S3 bucket reference",
                "cwe": "CWE-200",
            },
            "aws_s3_bucket": {
                "pattern": r"https?://s3[.\-][a-z0-9\-]+\.amazonaws\.com/[a-zA-Z0-9._-]+",
                "title": "AWS S3 bucket reference (path-style)",
                "cwe": "CWE-200",
            },
            "gcs_bucket": {
                "pattern": r"https?://[a-zA-Z0-9._-]+\.storage\.googleapis\.com",
                "title": "GCS bucket reference",
                "cwe": "CWE-200",
            },
            "azure_blob": {
                "pattern": r"https?://[a-zA-Z0-9]+\.blob\.core\.windows\.net/[a-zA-Z0-9._-]+",
                "title": "Azure Blob storage reference",
                "cwe": "CWE-200",
            },
            "digitalocean_space": {
                "pattern": r"https?://[a-zA-Z0-9._-]+\.(?:nyc3|ams3|sgp1|fra1|sfo3|sfo2)\.digitaloceanspaces\.com",
                "title": "DigitalOcean Space reference",
                "cwe": "CWE-200",
            },
        }

        open_bucket_indicators = {
            "aws_s3_open": [
                r"NoSuchBucket",
                r"NoSuchKey",
                r"AccessDenied",
                r"AllAccessDisabled",
                r"<Bucket>([^<]+)</Bucket>",
                r"ListBucketResult",
            ],
            "gcs_open": [
                r"NoSuchBucket",
                r"AccessDenied",
                r"Bucket is a required parameter",
            ],
            "azure_open": [
                r"ResourceNotFound",
                r"PublicAccessNotPermitted",
                r"<Error><Code>ContainerNotFound",
            ],
        }

        for _, meta in patterns.items():
            matches = re.findall(meta["pattern"], body, re.IGNORECASE)
            for match in matches:
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title=meta["title"],
                    description=f"Cloud storage bucket URL found in response body: {match}",
                    evidence=f"URL: {match}\nStatus: {status}",
                    remediation="Ensure the bucket is not publicly writable. Use signed URLs for temporary access.",
                    cwe=meta["cwe"],
                ))

        for bucket_type, indicators in open_bucket_indicators.items():
            for indicator in indicators:
                if re.search(indicator, body, re.IGNORECASE):
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title=f"Potential open {bucket_type.replace('_', ' ').upper()} detected",
                        description=f"Response contains indicator '{indicator}' suggesting an open or misconfigured cloud storage bucket.",
                        evidence=f"Indicator: {indicator}\nStatus: {status}",
                        remediation="Review cloud storage bucket permissions. Ensure buckets are not publicly accessible.",
                        cwe="CWE-200",
                    ))

        return results

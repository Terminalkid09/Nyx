import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


class ActiveOpenBucketCheck(BaseCheck):
    name = "active_open_bucket"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        hostname = parsed.netloc.split(":")[0]

        bucket_domains = [
            f"https://{hostname}.s3.amazonaws.com",
            f"https://{hostname}.s3.us-east-1.amazonaws.com",
            f"https://s3.amazonaws.com/{hostname}",
            f"https://{hostname}.storage.googleapis.com",
            f"https://{hostname}.blob.core.windows.net",
        ]

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for url in bucket_domains:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        if "ListBucketResult" in resp.text or "Contents" in resp.text or "Blob" in resp.text or "Name" in resp.text:
                            results.append(CheckResult(
                                triggered=True,
                                severity="critical",
                                title="Open Cloud Storage Bucket",
                                description=f"Cloud storage bucket appears to be publicly listable at {url}.",
                                evidence=f"URL: {url}\nStatus: 200 OK\nContents listable",
                                remediation="Block public list access. Use IAM policies, bucket policies, or signed URLs.",
                                cwe="CWE-200",
                            ))
                    elif resp.status_code == 403:
                        results.append(CheckResult(
                            triggered=True,
                            severity="low",
                            title="Cloud Storage Bucket Exists (Access Denied)",
                            description=f"Cloud storage bucket exists at {url} but returned 403.",
                            evidence=f"URL: {url}\nStatus: 403",
                            remediation="Ensure bucket has proper access controls. Check if listing is intentionally blocked.",
                            cwe="CWE-200",
                        ))
                except Exception:
                    continue
        return results

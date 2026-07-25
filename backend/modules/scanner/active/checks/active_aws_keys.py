import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse, parse_qsl, urlencode


AWS_KEY_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)aws_secret_access_key\s*[:=]\s*['\"]([^'\"]+)", "AWS Secret Key"),
    (r"(?i)aws_access_key_id\s*[:=]\s*['\"]([^'\"]+)", "AWS Access Key ID"),
    (r"-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key"),
    (r"-----BEGIN DSA PRIVATE KEY-----", "DSA Private Key"),
    (r"-----BEGIN EC PRIVATE KEY-----", "EC Private Key"),
    (r"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH Private Key"),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Token"),
    (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Live Key"),
    (r"pk_live_[0-9a-zA-Z]{24}", "Stripe Live Publishable Key"),
    (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "Slack Token"),
]


class ActiveAwsKeysCheck(BaseCheck):
    name = "active_aws_keys"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                modified = dict(base_request)
                parsed = urlparse(modified["url"])
                params = dict(parse_qsl(parsed.query))
                if param in params:
                    params[param] = "AKIAIOSFODNN7EXAMPLE"
                    modified["url"] = parsed._replace(query=urlencode(params)).geturl()
                    try:
                        resp = await client.request(**modified)
                        text = f"{resp.text} {dict(resp.headers)}"
                        for pattern, key_type in AWS_KEY_PATTERNS:
                            if re.search(pattern, text):
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="high",
                                    title="Sensitive Key Exposed",
                                    description=f"Potential {key_type} found in response.",
                                    evidence=f"Pattern matched: {key_type}",
                                    remediation="Rotate exposed keys immediately. Remove keys from source code and use env vars or secret managers.",
                                    cwe="CWE-798",
                                ))
                                break
                    except Exception:
                        continue
        return results

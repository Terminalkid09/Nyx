import re
from modules.scanner.base_check import BaseCheck, CheckResult

SENSITIVE_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "high", "CWE-798"),
    (r'(?i)api.?key\s*=\s*["\']?[A-Za-z0-9_\-]{16,64}', "API Key in response", "high", "CWE-798"),
    (r'(?i)password\s*=\s*["\']?[^"\'&\s]{6,}', "Password in response", "critical", "CWE-259"),
    (r'(?i)secret\s*=\s*["\']?[A-Za-z0-9_\-]{8,}', "Secret key in response", "high", "CWE-798"),
    (r'(?i)(sk_live|pk_live)_[A-Za-z0-9]{24,}', "Stripe live API key", "critical", "CWE-798"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token", "critical", "CWE-798"),
    (r'[-\w.]+@[-\w.]+\.(com|org|net|io|gov|edu)', "Email address in response", "low", "CWE-200"),
    (r'(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}', "Bearer token in response", "critical", "CWE-798"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private key in response", "critical", "CWE-312"),
]


class SensitiveDataExposureCheck(BaseCheck):
    name = "sensitive_data_exposure"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("body", "") or ""
        if not body.strip():
            return results

        for pattern, title, severity, cwe in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, body)
            if matches:
                evidence = matches[0] if isinstance(matches[0], str) else matches[0][0]
                results.append(CheckResult(
                    triggered=True,
                    severity=severity,
                    title=title,
                    description=f"Potential sensitive information found in response body: {title}",
                    evidence=evidence[:200],
                    remediation="Remove sensitive data from responses. Use environment variables and server-side only storage.",
                    cwe=cwe,
                ))

        return results

"""Passive information disclosure detection.

Scans every response for:
  - Credit card numbers (Luhn-validated PANs)
  - Social Security Numbers (US SSN format)
  - API keys & tokens (AWS, GitHub, Stripe, Slack, Google, generic JWT)
  - Internal IP addresses in response bodies
  - Stack traces & debug output
  - Email addresses (PII leak)
  - Database connection strings

Designed to run on EVERY response — must be fast (< 1ms per check).
All regex patterns are compiled once at module load.
"""
import re
from modules.scanner.base_check import BaseCheck, CheckResult

# ── Compiled patterns (module-level, loaded once) ──────────────────────────

# Luhn-validatable PANs: 13-19 digits with common spacing
# Matches: 4111111111111111, 4111-1111-1111-1111, 4111 1111 1111 1111
_CC_PATTERN = re.compile(
    r'\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2})|3(?:0[0-5]|[68][0-9])[0-9])'
    r'(?:[ -]?[0-9]{4}){2,4}\b'
)

_SSN_PATTERN = re.compile(r'\b(?!000|666|9\d{2})(\d{3})[- ]?(?!00)(\d{2})[- ]?(?!0000)(\d{4})\b')

_API_KEY_PATTERNS = [
    (re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'), 'AWS Access Key'),
    (re.compile(r'(?i)github[_\- ]?(?:token|pat)[\s:=]+(ghp_[A-Za-z0-9]{36})'), 'GitHub Token'),
    (re.compile(r'(?i)sk[-_]live[_\- ][A-Za-z0-9]{24,}'), 'Stripe Secret Key'),
    (re.compile(r'(?i)xox[baprs]-[A-Za-z0-9-]{10,}'), 'Slack Bot Token'),
    (re.compile(r'(?i)AIza[0-9A-Za-z\-_]{35}'), 'Google API Key'),
    (re.compile(r'(?i)eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*'), 'JWT Token'),
    (re.compile(r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)[\s:=]+([A-Za-z0-9+/=]{20,})'), 'Generic API Key'),
]

_INTERNAL_IP_PATTERN = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
)

_STACK_TRACE_PATTERNS = [
    (re.compile(r'(?i)Traceback\s*\(most\s+recent\s+call\s+last\)'), 'Python Traceback'),
    (re.compile(r'(?i)(?:Caused by:|Exception in thread|\.java:\d+\))'), 'Java Stack Trace'),
    (re.compile(r'(?i)stack trace:|\.(?:rb|php|js|tsx?|py):\d+(?::in\s+|\))'), 'Generic Stack Trace'),
    (re.compile(r'(?i)(?:Warning|Fatal error|Parse error|Uncaught):\s+.+in\s+'), 'PHP Error'),
    (re.compile(r'(?i)Server Error in\s+.+Application'), 'ASP.NET Error'),
]

_EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

_DB_STRING_PATTERNS = [
    (re.compile(r'(?i)(?:jdbc|mongodb|postgres|mysql|sqlite|redis|mssql)://[^\s<>"\'{}|\\^`[\]]+'), 'Database URL'),
    (re.compile(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\'&<>]{4,})["\']?'), 'Exposed Password'),
]

_SEVERITY_FOR_FINDING: dict[str, str] = {
    'Credit Card Number': 'critical',
    'SSN': 'high',
    'Database URL': 'critical',
    'Exposed Password': 'critical',
    'AWS Access Key': 'critical',
    'GitHub Token': 'critical',
    'Stripe Secret Key': 'critical',
    'Slack Bot Token': 'high',
    'Google API Key': 'medium',
    'JWT Token': 'medium',
    'Generic API Key': 'medium',
    'Internal IP': 'low',
    'Email Address': 'info',
}


class PassiveInfoDisclosureCheck(BaseCheck):
    """Scan every response for sensitive data leaks."""

    name = "passive_info_disclosure"

    def _luhn_check(self, number: str) -> bool:
        """Validate a credit card number using the Luhn algorithm."""
        digits = [int(c) for c in number if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        parity = len(digits) % 2
        for i, d in enumerate(digits):
            if i % 2 == parity:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results: list[CheckResult] = []

        # Only scan responses with bodies
        body = event.get("body") or ""
        if not body or not isinstance(body, str):
            return results
        # Cap to 500KB for performance
        body = body[:500_000]

        # ── Credit Card Numbers ─────────────────────────────────────
        cc_matches = _CC_PATTERN.findall(body)
        seen_cc: set[str] = set()
        for match in cc_matches:
            clean = match.strip() if isinstance(match, str) else match[0]
            clean = re.sub(r'[ -]', '', clean)
            if clean in seen_cc:
                continue
            seen_cc.add(clean)
            if self._luhn_check(clean):
                results.append(CheckResult(
                    triggered=True, severity='critical',
                    title='Credit Card Number in Response',
                    description='A credit card number was detected in the response body.',
                    evidence=f'PAN: {clean[:6]}... (Luhn-valid, {len(clean)} digits)',
                    remediation='Never include credit card data in HTTP responses. Use tokenization for any PAN handling.',
                    cwe='CWE-201',
                ))

        # ── SSN ─────────────────────────────────────────────────────
        ssn_matches = _SSN_PATTERN.findall(body)
        seen_ssn: set[str] = set()
        for g1, g2, g3 in ssn_matches:
            key = f"{g1}-{g2}-{g3}"
            if key in seen_ssn:
                continue
            seen_ssn.add(key)
            results.append(CheckResult(
                triggered=True, severity='high',
                title='Social Security Number in Response',
                description='A US Social Security Number was detected in the response.',
                evidence=f'SSN: {g1}-XX-{g3}',
                remediation='Redact SSNs from all responses. Use masked display (XXX-XX-1234) if necessary.',
                cwe='CWE-359',
            ))

        # ── API Keys ────────────────────────────────────────────────
        seen_keys: set[str] = set()
        for pattern, key_type in _API_KEY_PATTERNS:
            for match in pattern.finditer(body):
                val = match.group(0).strip()
                if val in seen_keys:
                    continue
                seen_keys.add(val)
                results.append(CheckResult(
                    triggered=True,
                    severity=_SEVERITY_FOR_FINDING.get(key_type, 'medium'),
                    title=f'{key_type} in Response',
                    description=f'A {key_type} was found in the response body.',
                    evidence=f'Key type: {key_type}',
                    remediation='Remove API keys from responses. Use environment variables. Rotate any exposed keys immediately.',
                    cwe='CWE-798',
                ))

        # ── Internal IPs ────────────────────────────────────────────
        ip_matches = _INTERNAL_IP_PATTERN.findall(body)
        seen_ip: set[str] = set()
        for ip in ip_matches:
            if ip in seen_ip:
                continue
            seen_ip.add(ip)
            results.append(CheckResult(
                triggered=True, severity='low',
                title='Internal IP Address in Response',
                description=f'Internal IP {ip} found in response body.',
                evidence=f'IP: {ip}',
                remediation='Remove internal IP addresses from public responses.',
                cwe='CWE-200',
            ))

        # ── Stack Traces ────────────────────────────────────────────
        for pattern, lang in _STACK_TRACE_PATTERNS:
            m = pattern.search(body)
            if m:
                snippet = body[max(0, m.start()-40):m.end()+60]
                results.append(CheckResult(
                    triggered=True, severity='medium',
                    title=f'{lang} in Response',
                    description='A stack trace or debug error was found in the response.',
                    evidence=snippet[:250],
                    remediation='Disable debug mode and detailed error messages in production. Use generic error pages.',
                    cwe='CWE-209',
                ))
                break  # One stack trace is enough

        # ── Email Addresses (PII) ───────────────────────────────────
        email_matches = _EMAIL_PATTERN.findall(body)
        seen_email: set[str] = set()
        for email in email_matches:
            email_lower = email.lower()
            # Skip well-known no-reply addresses and common placeholders
            if any(skip in email_lower for skip in ('example.', 'test@', 'noreply@', 'no-reply@', '@example', '@test', '@yourdomain')):
                continue
            if email in seen_email:
                continue
            seen_email.add(email)
            if len(seen_email) > 3:  # Only report first 3
                break
            results.append(CheckResult(
                triggered=True, severity='low',
                title='Email Address in Response',
                description=f'Email address {email} found in response body.',
                evidence=f'Email: {email}',
                remediation='Avoid exposing user email addresses in public responses unless necessary.',
                cwe='CWE-200',
            ))

        # ── Database Connection Strings ─────────────────────────────
        for pattern, desc in _DB_STRING_PATTERNS:
            m = pattern.search(body)
            if m:
                redacted = m.group(0)
                if 'password' in desc.lower():
                    redacted = re.sub(r'(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\'&<>]{4,})', r'\1=***', redacted)
                results.append(CheckResult(
                    triggered=True,
                    severity=_SEVERITY_FOR_FINDING.get(desc, 'high'),
                    title=f'{desc} in Response',
                    description=f'A {desc} was found in the response body.',
                    evidence=redacted[:200],
                    remediation='Remove database credentials and connection strings from responses immediately.',
                    cwe='CWE-200',
                ))

        return results
import json
import re
from modules.scanner.base_check import BaseCheck, CheckResult


class AuthPasswordAutocompleteCheck(BaseCheck):
    name = "auth_password_autocomplete"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        password_fields = re.finditer(r'<input[^>]*type\s*=\s*["\']?password["\']?[^>]*>', body, re.IGNORECASE)
        for match in password_fields:
            field = match.group(0)
            if 'autocomplete="off"' not in field.lower() and "autocomplete='off'" not in field.lower():
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title="Password field without autocomplete=off",
                    description="A password input field was found without autocomplete='off', allowing browser password autofill.",
                    evidence=f"Field HTML: {field[:200]}",
                    remediation='Add autocomplete="off" or autocomplete="new-password" to password input fields.',
                    cwe="CWE-549",
                ))
        return results

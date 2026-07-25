import re
from modules.scanner.base_check import BaseCheck, CheckResult


class AuthVerboseErrorsCheck(BaseCheck):
    name = "auth_verbose_errors"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        user_enum_patterns = [
            (r"Invalid username", "Specific 'Invalid username' message"),
            (r"Username not found", "Specific 'Username not found' message"),
            (r"Account does not exist", "Specific 'Account does not exist' message"),
            (r"Unknown user", "Specific 'Unknown user' message"),
            (r"User does not exist", "Specific 'User does not exist' message"),
            (r"Invalid email address", "Specific 'Invalid email address' message"),
            (r"No account found with that email", "Specific account lookup message"),
            (r"This username is not registered", "Specific 'not registered' message"),
            (r"Password is incorrect", "Specific password error without username context"),
            (r"Incorrect password", "Specific 'Incorrect password' message"),
        ]
        for pattern, desc in user_enum_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Verbose login error messages (user enumeration)",
                    description=f"{desc}. Distinct error messages for invalid usernames vs invalid passwords allow user enumeration.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:300]}",
                    remediation="Use generic error messages for login failures (e.g., 'Invalid username or password').",
                    cwe="CWE-203",
                ))
                break
        return results

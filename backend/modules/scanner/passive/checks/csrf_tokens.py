import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CsrfTokenCheck(BaseCheck):
    name = "csrf_tokens"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("body", "") or ""
        content_type = (event.get("headers", {}) or {}).get("content-type", "")

        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return results

        form_pattern = re.compile(
            r'<form[^>]*>.*?</form>',
            re.IGNORECASE | re.DOTALL
        )
        input_pattern = re.compile(
            r'<input[^>]+type=["\']?hidden["\']?[^>]*>',
            re.IGNORECASE
        )

        csrf_keywords = [
            "csrf", "csrf_token", "csrfmiddlewaretoken", "__csrf",
            "authenticity_token", "xsrf", "xsrf-token", "_token",
            "csrfToken", "csrf-token", "csrftoken", "token",
        ]

        forms = form_pattern.findall(body)
        for i, form in enumerate(forms):
            inputs = input_pattern.findall(form)
            has_csrf = False
            for inp in inputs:
                name_match = re.search(r'name=["\']([^"\']+)["\']', inp, re.IGNORECASE)
                if name_match:
                    name = name_match.group(1).lower()
                    if any(keyword in name for keyword in csrf_keywords):
                        has_csrf = True
                        break

            if not has_csrf:
                action_match = re.search(r'action=["\']([^"\']+)["\']', form, re.IGNORECASE)
                action = action_match.group(1) if action_match else "unspecified"
                method_match = re.search(r'method=["\']([^"\']+)["\']', form, re.IGNORECASE)
                method = method_match.group(1).upper() if method_match else "GET"

                if method in ("POST", "PUT", "DELETE", "PATCH"):
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title=f"Form #{i + 1} missing anti-CSRF token",
                        description=f"A {method} form (action: {action}) does not contain an anti-CSRF token.",
                        evidence=f"Form action: {action}\nMethod: {method}",
                        remediation="Add an anti-CSRF token (e.g., csrfmiddlewaretoken) as a hidden input field to all state-changing forms.",
                        cwe="CWE-352",
                    ))

        return results

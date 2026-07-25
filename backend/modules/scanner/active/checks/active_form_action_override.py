import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveFormActionOverrideCheck(BaseCheck):
    name = "active_form_action_override"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            try:
                resp = await client.get(base_request.get("url", ""))
                forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', resp.text, re.I)
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', resp.text, re.I)
                for form_action in forms:
                    if form_action.startswith("/") or form_action.startswith("http"):
                        for param in list(set(inputs) & set(target_params)):
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title="Form Action Override Possible",
                                description=f"Form action '{form_action}' may be overridable via parameter '{param}'.",
                                evidence=f"Form action: {form_action}\nParam: {param}",
                                remediation="Validate form action URLs server-side. Do not trust client-supplied form action parameters.",
                                cwe="CWE-345",
                            ))
            except Exception:
                pass
        return results

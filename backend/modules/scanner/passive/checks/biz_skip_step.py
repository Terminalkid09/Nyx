import re
from modules.scanner.base_check import BaseCheck, CheckResult


class BizSkipStepCheck(BaseCheck):
    name = "biz_skip_step"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        path = request_data.get("path", "") or ""
        step_params = re.findall(r"[?&](step|stage|page|section|phase)=(\d+)", url, re.IGNORECASE)
        for param, value in step_params:
            step_num = int(value)
            if step_num > 3:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Step skipping in wizards",
                    description=f"Workflow parameter '{param}={step_num}' detected. Directly accessing later steps may bypass validation or requirements.",
                    evidence=f"URL: {url}\nStep: {param}={step_num}",
                    remediation="Maintain wizard state server-side. Validate that users have completed prerequisite steps before allowing access to later stages.",
                    cwe="CWE-472",
                ))
                break
        return results

import re
from modules.scanner.base_check import BaseCheck, CheckResult


class PrototypePollutionServerCheck(BaseCheck):
    name = "prototype_pollution_server"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or ""
        url = event.get("url", "") or request_data.get("url", "")
        combined = f"{url} {body}"

        server_pp_patterns = [
            (r"__proto__", "Server-side __proto__ in request"),
            (r"__proto__\s*[=:]", "__proto__ assignment in request"),
            (r"constructor\s*[=:]\s*\{", "constructor object assignment"),
            (r"__proto__\s*\.\s*\w+\s*=", "__proto__ property assignment"),
            (r"\[\s*['\"]__proto__['\"]\s*\]", "__proto__ bracket notation"),
        ]
        for pattern, desc in server_pp_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Server-side prototype pollution detected",
                    description=f"{desc} found. Server-side prototype pollution can lead to authentication bypass or RCE.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Validate JSON input against a strict schema. Avoid recursive merge operations. Use Object.create(null) for dictionaries.",
                    cwe="CWE-1321",
                ))
                break
        return results

import re
from modules.scanner.base_check import BaseCheck, CheckResult


class PrototypePollutionClientCheck(BaseCheck):
    name = "prototype_pollution_client"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or ""
        url = event.get("url", "") or request_data.get("url", "")
        combined = f"{url} {body}"

        pp_patterns = [
            (r"__proto__", "Client-side __proto__ pollution"),
            (r"constructor\.prototype", "constructor.prototype pollution"),
            (r"Object\.assign\s*\(.*?__proto__", "Object.assign with __proto__"),
            (r"merge\s*\(.*?__proto__", "merge() with __proto__"),
            (r"extend\s*\(.*?__proto__", "extend() with __proto__"),
            (r"\$\.extend\s*\(.*?__proto__", "jQuery.extend with __proto__"),
            (r"\.constructor\s*=\s*", "constructor reassignment"),
        ]
        for pattern, desc in pp_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Client-side prototype pollution detected",
                    description=f"{desc} found. Prototype pollution can lead to XSS or property injection.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Use Object.create(null) for dictionaries. Freeze prototypes with Object.freeze(). Validate JSON input against schema. Use Map instead of plain objects.",
                    cwe="CWE-1321",
                ))
                break
        return results

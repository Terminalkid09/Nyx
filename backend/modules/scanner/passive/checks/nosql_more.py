import re
from modules.scanner.base_check import BaseCheck, CheckResult


class NosqlMoreCheck(BaseCheck):
    name = "nosql_more"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = event.get("url", "") or request_data.get("url", "")
        body = event.get("request_body", "") or ""
        response_body = event.get("response_body", "") or ""
        combined = f"{url} {body} {response_body}"

        nosql_patterns = [
            (r"\$ne", "NoSQL $ne operator"),
            (r"\$gt", "NoSQL $gt operator"),
            (r"\$regex", "NoSQL $regex operator"),
            (r"\$where", "NoSQL $where operator"),
            (r"\$nin", "NoSQL $nin operator"),
            (r"\$or", "NoSQL $or operator"),
            (r"\$and", "NoSQL $and operator"),
            (r"\$exists", "NoSQL $exists operator"),
            (r"\$in\s*:", "NoSQL $in operator"),
            (r"\$ne\s*:", "NoSQL $ne operator"),
        ]
        for pattern, desc in nosql_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="NoSQL injection variant detected",
                    description=f"{desc} found. NoSQL injection may allow authentication bypass or data access.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Validate and sanitize all user input. Use strict schema validation. Avoid passing raw user input to NoSQL queries.",
                    cwe="CWE-943",
                ))
                break
        return results

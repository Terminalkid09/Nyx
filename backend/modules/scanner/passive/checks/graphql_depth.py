import re
from modules.scanner.base_check import BaseCheck, CheckResult


class GraphqlDepthCheck(BaseCheck):
    name = "graphql_depth"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or event.get("body", "") or ""
        if "query" not in body and "mutation" not in body:
            return results
        depth = 0
        max_depth = 0
        for ch in body:
            if ch == "{":
                depth += 1
                max_depth = max(max_depth, depth)
            elif ch == "}":
                depth -= 1
        if max_depth >= 10:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="GraphQL query depth too deep",
                description=f"GraphQL query has a nesting depth of {max_depth}, which can lead to resource exhaustion.",
                evidence=f"Max depth: {max_depth}\nQuery: {body[:300]}",
                remediation="Implement query depth limiting on the GraphQL server. Limit nesting to a reasonable value (e.g., 5-7 levels).",
                cwe="CWE-400",
            ))
        return results

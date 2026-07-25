import re
from modules.scanner.base_check import BaseCheck, CheckResult


class GraphqlFieldSuggestionsCheck(BaseCheck):
    name = "graphql_field_suggestions"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        suggestion_patterns = [
            r"Did you mean",
            r"Cannot query field",
            r"Unknown field",
            r"Did you mean\s+['\"]\w+['\"]\s*\\?",
            r"Field\s+['\"]\w+['\"]\s+isn't",
        ]
        for pattern in suggestion_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="GraphQL field suggestions enabled",
                    description="GraphQL server returns field suggestions in error messages, which helps attackers discover the schema.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:500]}",
                    remediation="Disable field suggestions in production GraphQL environments to prevent schema discovery.",
                    cwe="CWE-200",
                ))
                break
        return results

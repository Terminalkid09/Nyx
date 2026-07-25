import re
from modules.scanner.base_check import BaseCheck, CheckResult


class GraphqlDebugCheck(BaseCheck):
    name = "graphql_debug"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        debug_patterns = [
            (r'"extensions"\s*:\s*\{[^}]*"debug', "GraphQL debug extensions enabled"),
            (r'"stacktrace"\s*:', "GraphQL stacktrace in response"),
            (r'"exception"\s*:\s*\{', "GraphQL exception details exposed"),
            (r'"internal"\s*:\s*\{', "GraphQL internal details exposed"),
            (r'"debugMessage"\s*:', "GraphQL debug message exposed"),
        ]
        for pattern, desc in debug_patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="GraphQL debug mode enabled",
                    description=f"{desc}. Debug information in GraphQL responses exposes internal details to attackers.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:500]}",
                    remediation="Disable debug mode and stack traces in production GraphQL environments.",
                    cwe="CWE-200",
                ))
                break
        return results

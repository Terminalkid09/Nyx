import re
from modules.scanner.base_check import BaseCheck, CheckResult


class GraphqlAliasesCheck(BaseCheck):
    name = "graphql_aliases"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or event.get("body", "") or ""
        if not body:
            return results
        alias_pattern = re.compile(r"\w+\s*:\s*\w+\s*\(")
        aliases = alias_pattern.findall(body)
        if len(aliases) >= 5:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="GraphQL aliases abuse detected",
                description=f"GraphQL query contains {len(aliases)} aliases, which can be used for batching attacks or rate limit bypass.",
                evidence=f"Alias count: {len(aliases)}\nQuery snippet: {body[:300]}",
                remediation="Implement alias-based rate limiting or limit the number of aliases per query on the GraphQL server.",
                cwe="CWE-400",
            ))
        return results

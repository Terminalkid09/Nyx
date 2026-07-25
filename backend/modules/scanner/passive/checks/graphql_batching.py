import re
from modules.scanner.base_check import BaseCheck, CheckResult


class GraphqlBatchingCheck(BaseCheck):
    name = "graphql_batching"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or event.get("body", "") or ""
        if not body:
            return results
        batch_pattern = re.compile(r'\{\s*("query"\s*:|"mutation"\s*:)')
        batch_matches = batch_pattern.findall(body)
        if len(batch_matches) > 1:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="GraphQL batching abuse detected",
                description=f"Request contains {len(batch_matches)} GraphQL operations in a single request, which can bypass rate limiting.",
                evidence=f"Operation count: {len(batch_matches)}\nBody: {body[:300]}",
                remediation="Implement per-operation rate limiting. Limit the number of operations per GraphQL request.",
                cwe="CWE-400",
            ))
        return results

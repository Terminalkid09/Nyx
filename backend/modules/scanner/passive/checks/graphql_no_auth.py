import re
from modules.scanner.base_check import BaseCheck, CheckResult


class GraphqlNoAuthCheck(BaseCheck):
    name = "graphql_no_auth"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        path = request_data.get("path", request_data.get("url", ""))
        if "/graphql" not in path.lower():
            return results
        auth_headers = ["authorization", "x-api-key", "api-key", "x-auth-token", "token"]
        has_auth = any(h in headers_lower for h in auth_headers)
        if not has_auth:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="Missing GraphQL authentication",
                description=f"GraphQL endpoint at {path} was accessed without any authentication header.",
                evidence=f"Path: {path}\nHeaders: {dict(headers_lower)[:200]}",
                remediation="Implement authentication for all GraphQL endpoints, including queries, mutations, and subscriptions.",
                cwe="CWE-287",
            ))
        return results

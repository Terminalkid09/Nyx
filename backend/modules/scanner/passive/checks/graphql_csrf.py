import re
from modules.scanner.base_check import BaseCheck, CheckResult


class GraphqlCsrfCheck(BaseCheck):
    name = "graphql_csrf"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        body = event.get("request_body", "") or event.get("body", "") or ""
        method = request_data.get("method", event.get("method", "GET")).upper()
        path = request_data.get("path", request_data.get("url", ""))
        if "/graphql" not in path.lower():
            return results
        if method in ("POST", "PUT", "DELETE", "PATCH") and ("mutation" in body.lower()):
            ct = headers_lower.get("content-type", "")
            if "application/json" not in ct:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="GraphQL CSRF via mutation",
                    description=f"GraphQL mutation sent with content-type '{ct}' instead of application/json. Some content-types allow CSRF.",
                    evidence=f"Method: {method}\nContent-Type: {ct}\nPath: {path}",
                    remediation="Require application/json content-type for GraphQL mutations. Add CSRF tokens or custom headers for state-changing operations.",
                    cwe="CWE-352",
                ))
        return results

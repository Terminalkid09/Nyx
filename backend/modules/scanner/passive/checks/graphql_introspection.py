import re
from modules.scanner.base_check import BaseCheck, CheckResult


class GraphQLIntrospectionCheck(BaseCheck):
    name = "graphql_introspection"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("body", "") or ""
        status = event.get("status")
        headers = event.get("headers", {}) or {}
        content_type = (headers.get("content-type") or headers.get("Content-Type") or "").lower()

        path = request_data.get("path", request_data.get("url", ""))

        is_graphql_path = re.search(r"/graphql", path, re.IGNORECASE)

        graphql_signatures = [
            '"__typename"',
            '"data"',
            '"__schema"',
            '"queryType"',
            '"mutationType"',
            '"subscriptionType"',
            '"types"',
            '"directives"',
            '"kind"',
            '"name"',
            '"description"',
            '"fields"',
            '"args"',
            '"type"',
            '"ofType"',
            "IntrospectionQuery",
            '"possibleTypes"',
            '"inputFields"',
            '"interfaces"',
            '"enumValues"',
        ]

        graphql_likely = sum(1 for sig in graphql_signatures if sig in body)

        if is_graphql_path and graphql_likely >= 3:
            title = "GraphQL introspection data exposed"
            severity = "high"
            desc = "GraphQL endpoint reveals its full schema via introspection, exposing all queries, mutations, and data types."
            remediation = "Disable introspection in production. Use a whitelist of allowed queries or disable the __schema field."
            cwe = "CWE-200"

            if '"__schema"' in body:
                results.append(CheckResult(
                    triggered=True,
                    severity=severity,
                    title=title,
                    description=desc,
                    evidence=f"URL: {path}\nSchema data detected in response body",
                    remediation=remediation,
                    cwe=cwe,
                ))
            else:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="GraphQL endpoint detected",
                    description=f"GraphQL endpoint found at {path} but introspection results are inconclusive.",
                    evidence=f"URL: {path}\nStatus: {status}",
                    remediation="Ensure GraphQL introspection is disabled in production.",
                    cwe=cwe,
                ))

        elif is_graphql_path and status == 200 and "application/json" in content_type:
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="GraphQL endpoint detected",
                description=f"A GraphQL endpoint was identified at {path}.",
                evidence=f"URL: {path}\nStatus: {status}\nContent-Type: {content_type}",
                remediation="Verify that introspection and dangerous features like batching are disabled.",
                cwe="CWE-200",
            ))

        return results

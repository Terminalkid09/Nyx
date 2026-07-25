import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveGraphqlMutationCheck(BaseCheck):
    name = "active_graphql_mutation"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            graphql_paths = ['/graphql', '/gql', '/api/graphql']
            test_mutation = {"query": "mutation { __typename }"}
            for path in graphql_paths:
                try:
                    resp = await client.post(f"{base_url}{path}", json=test_mutation, headers=req.get("headers", {}))
                    if resp.status_code == 200 and '"data"' in resp.text:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="GraphQL Mutation Without Authentication",
                            description=f"GraphQL mutation endpoint on {path} accepts unauthenticated mutation requests.",
                            evidence=f"Path: {path}\nStatus: {resp.status_code}",
                            remediation="Require authentication for all GraphQL mutations. Implement field-level authorization checks.",
                            cwe="CWE-306",
                        ))
                except Exception:
                    continue
        return results

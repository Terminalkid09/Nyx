import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveGraphqlIntrospectionCheck(BaseCheck):
    name = "active_graphql_introspection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            graphql_paths = ['/graphql', '/graphiql', '/gql', '/v1/graphql', '/api/graphql']
            for path in graphql_paths:
                try:
                    query = {"query": "{__schema{types{name}}}"}
                    resp = await client.post(f"{base_url}{path}", json=query, headers=req.get("headers", {}))
                    if resp.status_code == 200 and '"data"' in resp.text and '"__schema"' in resp.text:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="GraphQL Introspection Query Enabled",
                            description=f"Active query confirms GraphQL introspection is enabled on {path}, exposing the entire schema.",
                            evidence=f"Path: {path}\nResponse snippet: {resp.text[:500]}",
                            remediation="Disable introspection in production. Use allow-listing for GraphQL operations.",
                            cwe="CWE-200",
                        ))
                except Exception:
                    continue
        return results

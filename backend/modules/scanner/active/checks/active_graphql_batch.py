import json
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


class ActiveGraphqlBatchCheck(BaseCheck):
    name = "active_graphql_batch"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        graphql_paths = ["/graphql", "/graphql/", "/v1/graphql", "/api/graphql", "/gql", "/query"]

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for path in graphql_paths:
                target = f"{parsed.scheme}://{parsed.netloc}{path}"
                batch_payload = [
                    {"query": "{ __typename }"},
                    {"query": "{ __typename }"},
                    {"query": "mutation { dangerousOp { result } }"},
                ]
                try:
                    resp = await client.post(target, json=batch_payload, headers={"Content-Type": "application/json"})
                    if resp.status_code == 200 and isinstance(resp.json(), list) and len(resp.json()) > 1:
                        has_errors = any("errors" in r for r in resp.json())
                        results.append(CheckResult(
                            triggered=True,
                            severity="high" if not has_errors else "medium",
                            title="GraphQL Batching Allowed",
                            description=f"GraphQL endpoint at '{path}' accepts batched queries.",
                            evidence=f"URL: {target}\nBatch size: {len(batch_payload)}",
                            remediation="Implement query costing and rate limiting per request. Limit batch size.",
                            cwe="CWE-770",
                        ))
                except Exception:
                    continue
        return results

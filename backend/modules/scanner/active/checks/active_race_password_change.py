import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveRacePasswordChangeCheck(BaseCheck):
    name = "active_race_password_change"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            responses = []
            import asyncio
            tasks = []
            for i in range(5):
                tasks.append(client.request("POST", url, headers=req.get("headers", {})))
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for r in completed:
                if isinstance(r, Exception):
                    continue
                responses.append(r.status_code)
            if len(responses) >= 3 and len(set(responses)) == 1 and responses[0] in [200, 201, 202]:
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Race Condition - Concurrent Password Change",
                    description="Concurrent password change requests may allow session takeover or bypass current password validation.",
                    evidence=f"Sent 5 concurrent requests, got {len(responses)} responses with status {set(responses)}",
                    remediation="Use database transactions for password changes. Implement optimistic locking.",
                    cwe="CWE-362",
                ))
        return results

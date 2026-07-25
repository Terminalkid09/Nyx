import asyncio
import copy
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult

RACE_COUNT = 15
RACE_TIMEOUT = 10


class RaceConditionCheck(BaseCheck):
    name = "race_condition"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=RACE_TIMEOUT, follow_redirects=False) as client:
            original = None
            try:
                original = await client.request(**base_request)
            except Exception:
                return results

            if original.status_code not in (200, 201, 204, 302):
                return results

            tasks = [self._send_request(client, base_request) for _ in range(RACE_COUNT)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            successful = 0
            status_counts = {}
            for resp in responses:
                if isinstance(resp, httpx.Response):
                    successful += 1
                    status_counts[resp.status_code] = status_counts.get(resp.status_code, 0) + 1

            if len(status_counts) > 1:
                evidence_lines = [f"Status distribution:"]
                for status, count in sorted(status_counts.items()):
                    evidence_lines.append(f"  {status}: {count}")
                evidence_lines.append(f"Total concurrent requests: {RACE_COUNT}")

                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Possible race condition detected",
                    description=f"Concurrent requests resulted in different status codes, "
                                f"suggesting a potential race condition.",
                    evidence="\n".join(evidence_lines),
                    remediation="Use database transactions or application-level locks for critical operations. "
                                "Implement optimistic or pessimistic locking mechanisms.",
                    cwe="CWE-362",
                ))

            elif successful >= RACE_COUNT * 0.8:
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title="High concurrency tolerance - possible race condition",
                    description=f"All {successful}/{RACE_COUNT} concurrent requests succeeded. "
                                f"If this is a state-changing endpoint, race conditions may be exploitable.",
                    evidence=f"Concurrent requests: {successful}/{RACE_COUNT}\n"
                             f"Method: {base_request.get('method', 'GET')}\n"
                             f"URL: {base_request.get('url', '')}",
                    remediation="Ensure state-changing operations use proper locking and transaction isolation.",
                    cwe="CWE-362",
                ))

        return results

    async def _send_request(self, client: httpx.AsyncClient, req: dict) -> httpx.Response:
        try:
            return await client.request(**req)
        except Exception:
            raise

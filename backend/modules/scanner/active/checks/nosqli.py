import copy
import json
import re
import urllib.parse
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult

NOSQLI_PAYLOADS = [
    ('$ne', '{"$ne": ""}'),
    ('$ne_password', '{"$ne": ""}'),
    ('$gt', '{"$gt": ""}'),
    ('$gte', '{"$gte": ""}'),
    ('$regex', '{"$regex": ".*"}'),
    ('$exists', '{"$exists": true}'),
    ('$ne_string', '{"$ne": "invalid"}'),
    ('$gt_string', '{"$gt": ""}'),
    ('$nin', '{"$nin": []}'),
    ('or_query', '{"$or": [{"$ne": ""}, {"$ne": ""}]}'),
]


class NoSqlInjectionCheck(BaseCheck):
    name = "nosqli"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        original_body = base_request.get("content", base_request.get("data", ""))
        is_json_body = False
        if original_body:
            try:
                json.loads(original_body)
                is_json_body = True
            except (json.JSONDecodeError, TypeError):
                pass

        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                for payload_name, payload_value in NOSQLI_PAYLOADS:
                    modified = copy.deepcopy(base_request)

                    if is_json_body:
                        try:
                            body = json.loads(modified.get("content", modified.get("data", "{}")))
                            if isinstance(body, dict):
                                if param in body:
                                    body[param] = json.loads(payload_value)
                                    modified["content"] = json.dumps(body)
                                    modified["headers"] = {
                                        **dict(modified.get("headers", {})),
                                        "Content-Type": "application/json",
                                    }
                        except Exception:
                            continue
                    else:
                        parsed = urllib.parse.urlparse(modified["url"])
                        params = dict(urllib.parse.parse_qsl(parsed.query))
                        params[param] = payload_value
                        modified["url"] = parsed._replace(
                            query=urllib.parse.urlencode(params)
                        ).geturl()

                    try:
                        resp = await client.request(**modified)
                        body_lower = resp.text.lower() if resp.text else ""

                        error_patterns = [
                            r"mongodb",
                            r"mongoservererror",
                            r"unexpected token",
                            r"query failed",
                            r"mongoerror",
                            r"E11000",
                            r"duplicate key",
                            r"CastError",
                            r"Cast to [a-z]+ failed",
                            r"ValidationError",
                            r"Path .* is required",
                        ]
                        for pattern in error_patterns:
                            if re.search(pattern, body_lower):
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="high",
                                    title="NoSQL injection error detected",
                                    description=f"Parameter '{param}' triggered a NoSQL/MongoDB error "
                                                f"with payload '{payload_name}'.",
                                    evidence=f"Payload: {payload_value}\nError pattern: {pattern}\nStatus: {resp.status_code}",
                                    remediation="Use parameterised queries or validate user input against a whitelist. "
                                                "Sanitize input for MongoDB operators ($ne, $gt, $regex, etc.).",
                                    cwe="CWE-943",
                                ))
                                break

                        if resp.status_code == 200 and payload_name in ("$ne", "$gt", "$regex"):
                            original_resp = await self._send_original(client, base_request)
                            if original_resp and resp.text != original_resp.text:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="medium",
                                    title="Possible NoSQL injection (behavioral change)",
                                    description=f"Parameter '{param}' with '{payload_name}' "
                                                f"caused a different response from the original.",
                                    evidence=f"Payload: {payload_value}\nOriginal status: {original_resp.status_code}\n"
                                             f"Modified status: {resp.status_code}",
                                    remediation="Sanitize input to prevent MongoDB operator injection.",
                                    cwe="CWE-943",
                                ))
                    except Exception:
                        continue

        return results

    async def _send_original(self, client: httpx.AsyncClient, base: dict) -> httpx.Response | None:
        try:
            return await client.request(**base)
        except Exception:
            return None

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req

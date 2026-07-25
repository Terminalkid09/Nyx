import copy
import json
import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class NoSqlInjectionActiveCheck(BaseCheck):
    name = "active_nosql_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        payloads = [
            ('$where', '1=1'),
            ('$ne', ''),
            ('$gt', ''),
            ('$regex', '.*'),
            ('$exists', 'true'),
            ('$nin', '[]'),
        ]
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                for op, val in payloads:
                    modified = copy.deepcopy(base_request)
                    body = modified.get("content", modified.get("data", "{}"))
                    try:
                        body_json = json.loads(body) if isinstance(body, str) else body
                    except json.JSONDecodeError:
                        body_json = {}
                    if isinstance(body_json, dict):
                        body_json[param] = {op: val}
                        modified["content"] = json.dumps(body_json)
                    try:
                        resp = await client.request(**modified)
                        if resp.status_code not in (400, 500) and resp.status_code < 500:
                            error_patterns = [r"mongodb", r"mongo.*error", r"E11000", r"CastError", r"ValidationError", r"path.*required"]
                            for pattern in error_patterns:
                                if re.search(pattern, resp.text, re.IGNORECASE):
                                    results.append(CheckResult(
                                        triggered=True,
                                        severity="high",
                                        title="NoSQL injection detected ($where, $ne)",
                                        description=f"Parameter '{param}' with operator '{op}' triggered a database error.",
                                        evidence=f"Operator: {op}\nValue: {val}\nPattern: {pattern}",
                                        remediation="Sanitize user input for MongoDB operators. Use strict schema validation.",
                                        cwe="CWE-943",
                                    ))
                                    break
                    except Exception:
                        continue
        return results

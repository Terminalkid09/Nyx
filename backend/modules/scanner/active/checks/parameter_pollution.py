import copy
import json
import urllib.parse
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class ParameterPollutionCheck(BaseCheck):
    name = "parameter_pollution"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        method = base_request.get("method", "GET").upper()
        parsed = urllib.parse.urlparse(base_request["url"])
        query_params = dict(urllib.parse.parse_qsl(parsed.query))

        if not query_params and not target_params:
            return results

        target_params = target_params or list(query_params.keys())

        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                original_val = query_params.get(param, "original")
                test_vals = ["polluted1", "polluted2", "polluted3"]

                tests = [
                    {
                        "name": "Multiple query params with same name",
                        "mod": lambda: parsed._replace(
                            query=urllib.parse.urlencode(
                                [(param, "first"), (param, "second")]
                            )
                        ).geturl(),
                    },
                ]

                for test in tests:
                    modified = copy.deepcopy(base_request)
                    modified["url"] = test["mod"]()

                    try:
                        resp = await client.request(**modified)
                        if resp.status_code == 200:
                            body_lower = resp.text.lower() if resp.text else ""
                            if "first" in body_lower or "second" in body_lower:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="medium",
                                    title=f"HTTP Parameter Pollution: '{param}'",
                                    description=f"Parameter '{param}' with duplicate values "
                                                f"resulted in both values appearing in response.",
                                    evidence=f"Parameter: {param}\nValues: first, second\nStatus: {resp.status_code}",
                                    remediation="Use only the first or last occurrence consistently. "
                                                "Reject requests with duplicate parameter names.",
                                    cwe="CWE-235",
                                ))
                    except Exception:
                        continue

                if method in ("POST", "PUT", "PATCH"):
                    content_type = (base_request.get("headers", {}) or {}).get("Content-Type", "")

                    body_tests = []
                    if "application/x-www-form-urlencoded" in content_type:
                        body_tests.append({
                            "name": "Form body + query param",
                            "body": urllib.parse.urlencode(
                                [(param, "form_value1"), (param, "form_value2")]
                            ),
                            "url": parsed._replace(
                                query=urllib.parse.urlencode({param: "query_value"})
                            ).geturl(),
                        })
                    elif "application/json" in content_type:
                        body_tests.append({
                            "name": "JSON body with different param type",
                            "body": json.dumps({param: "json_value"}),
                            "url": parsed._replace(
                                query=urllib.parse.urlencode({param: "query_value"})
                            ).geturl(),
                        })

                    for body_test in body_tests:
                        modified = copy.deepcopy(base_request)
                        modified["content"] = body_test["body"]
                        modified["url"] = body_test["url"]

                        try:
                            resp = await client.request(**modified)
                            if resp.status_code == 200:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="medium",
                                    title=f"HTTP Parameter Pollution: '{param}' ({body_test['name']})",
                                    description=f"Parameter '{param}' sent both in query string and request body "
                                                f"resulted in a successful response.",
                                    evidence=f"Parameter: {param}\nTest: {body_test['name']}\nStatus: {resp.status_code}",
                                    remediation="Use a consistent location for each parameter. "
                                                "Reject requests with the same parameter in multiple locations.",
                                    cwe="CWE-235",
                                ))
                        except Exception:
                            continue

        return results

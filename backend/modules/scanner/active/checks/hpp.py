import copy
import urllib.parse
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class HppCheck(BaseCheck):
    name = "hpp"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                parsed = urllib.parse.urlparse(base_request["url"])
                qs_params = dict(urllib.parse.parse_qsl(parsed.query))
                if param not in qs_params:
                    continue

                tests = [
                    {
                        "name": "Duplicate parameter (same value)",
                        "params": [(param, qs_params[param]), (param, qs_params[param])],
                    },
                    {
                        "name": "Duplicate parameter (different values)",
                        "params": [(param, "first_value"), (param, "second_value")],
                    },
                    {
                        "name": "Multiple copies of same parameter",
                        "params": [(param, "1"), (param, "2"), (param, "3"), (param, "4"), (param, "5")],
                    },
                    {
                        "name": "Parameter with empty value alongside real value",
                        "params": [(param, ""), (param, qs_params[param])],
                    },
                ]

                for test in tests:
                    modified = copy.deepcopy(base_request)
                    new_qs = urllib.parse.urlencode(test["params"])
                    modified["url"] = parsed._replace(query=new_qs).geturl()

                    try:
                        resp = await client.request(**modified)
                        body_lower = resp.text.lower() if resp.text else ""

                        response_indicators = []
                        for _, val in test["params"]:
                            if val and val.lower() in body_lower:
                                response_indicators.append(val)

                        if len(response_indicators) > 1 or (
                            len(test["params"]) > 1 and
                            test["params"][0][1] in body_lower
                        ):
                            first_val = qs_params[param]
                            test_vals = [p[1] for p in test["params"] if p[1]]

                            if test_vals:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="medium",
                                    title=f"HTTP Parameter Pollution possible: '{param}'",
                                    description=f"Parameter '{param}' was duplicated and values appear in the response, "
                                                f"indicating potential HPP vulnerability.",
                                    evidence=f"Test: {test['name']}\n"
                                             f"Parameters: {test['params']}\nStatus: {resp.status_code}",
                                    remediation="Use the last or first occurrence of duplicate parameters consistently. "
                                                "Validate and reject requests with duplicate parameters.",
                                    cwe="CWE-235",
                                ))
                    except Exception:
                        continue

        return results

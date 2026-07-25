import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


class ActiveTomcatManagerCheck(BaseCheck):
    name = "active_tomcat_manager"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        paths = ["/manager/html", "/manager/", "/host-manager/html", "/admin/", "/jmx-console/"]
        creds = [("admin", "admin"), ("admin", "password"), ("admin", "tomcat"), ("tomcat", "tomcat"), ("admin", "admin123")]

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for path in paths:
                try:
                    resp = await client.get(f"{base_url}{path}")
                    if resp.status_code == 200 and ("tomcat" in resp.text.lower() or "application manager" in resp.text.lower()):
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Tomcat Manager Exposed",
                            description=f"Tomcat manager interface exposed at '{path}'.",
                            evidence=f"URL: {base_url}{path}\nStatus: {resp.status_code}",
                            remediation="Restrict manager endpoints to localhost. Remove default credentials. Use strong authentication.",
                            cwe="CWE-287",
                        ))
                        break
                except Exception:
                    continue

            import base64
            for path in ["/manager/html", "/manager/"]:
                for user, pwd in creds:
                    try:
                        auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                        resp = await client.get(f"{base_url}{path}", headers={"Authorization": f"Basic {auth}"})
                        if resp.status_code == 200 and "tomcat" in resp.text.lower():
                            results.append(CheckResult(
                                triggered=True,
                                severity="critical",
                                title="Tomcat Manager Default Credentials",
                                description=f"Default credentials '{user}:{pwd}' work on Tomcat manager.",
                                evidence=f"URL: {base_url}{path}\nCredentials: {user}:{pwd}",
                                remediation="Change all default credentials immediately. Use strong passwords and disable manager external access.",
                                cwe="CWE-798",
                            ))
                            break
                    except Exception:
                        continue
        return results

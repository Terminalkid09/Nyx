import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveAuthPrivilegeEscalationCheck(BaseCheck):
    name = "active_auth_privilege_escalation"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        user_headers = [
            {"X-Role": "admin", "X-User-Role": "admin"},
            {"X-User-Is-Admin": "true", "X-Admin": "true"},
            {"impersonated-user": "admin", "sudo": "true"},
        ]
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for headers in user_headers:
                try:
                    req = {**base_request, "headers": {**base_request.get("headers", {}), **headers}}
                    resp = await client.request(
                        method=req.get("method", "GET"),
                        url=req.get("url", ""),
                        headers=req.get("headers", {}),
                    )
                    body_lower = resp.text.lower()
                    if any(x in body_lower for x in ["admin panel", "admin dashboard", "user management", "admin"]):
                        if resp.status_code == 200:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="Privilege Escalation via Header Manipulation",
                                description=f"Access to admin functionality achieved by adding {headers}",
                                evidence=f"Headers: {headers}\nStatus: {resp.status_code}\nContains admin panel: True",
                                remediation="Do not rely on client-side headers for authorization. Validate server-side.",
                                cwe="CWE-269",
                            ))
                            break
                except Exception:
                    continue
        return results


class ActiveAuthIdorCheck(BaseCheck):
    name = "active_auth_idor"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        if not target_params:
            return results
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params[:5]:
                for test_id in ["1", "2", "100", "99999", "0", "-1", "admin", "other_user"]:
                    try:
                        url = base_request.get("url", "")
                        if param in url:
                            test_url = url.replace(f"{param}=", f"{param}={test_id}")
                        else:
                            test_url = url
                        resp = await client.get(test_url, headers=base_request.get("headers", {}))
                        body = resp.text.lower()
                        if test_id in body and resp.status_code == 200:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="Insecure Direct Object Reference (IDOR)",
                                description=f"Parameter {param}={test_id} returned data for a different object",
                                evidence=f"Param: {param}, Value: {test_id}, Status: {resp.status_code}",
                                remediation="Implement proper access control checks for every object reference.",
                                cwe="CWE-639",
                            ))
                            break
                    except Exception:
                        continue
        return results


class ActiveAuthSessionFixationCheck(BaseCheck):
    name = "active_auth_session_fixation"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        fixed_sessions = [
            "PHPSESSID=attacker_session_value",
            "JSESSIONID=attacker_session_value",
            "ASP.NET_SessionId=attacker_session_value",
            "session=attacker_session_value",
            "sid=attacker_session_value",
        ]
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for cookie_header in fixed_sessions:
                try:
                    headers = {**base_request.get("headers", {}), "Cookie": cookie_header}
                    resp = await client.get(base_request.get("url", ""), headers=headers)
                    set_cookie = resp.headers.get("set-cookie", "")
                    if "attacker_session_value" in set_cookie or "PHPSESSID" in resp.text:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Session Fixation Vulnerability",
                            description=f"Server accepted and reused attacker-specified session {cookie_header.split('=')[0]}",
                            evidence=f"Cookie: {cookie_header}\nResponse Set-Cookie: {set_cookie}",
                            remediation="Regenerate session ID after successful authentication. Never accept externally-provided session IDs.",
                            cwe="CWE-384",
                        ))
                        break
                except Exception:
                    continue
        return results


class ActiveAuthRoleManipulationCheck(BaseCheck):
    name = "active_auth_role_manipulation"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        role_payloads = [
            {"Cookie": "role=admin; user_type=premium; is_admin=true"},
            {"X-Role": "admin", "Authorization": "Bearer admin_token"},
            {"Cookie": "group=administrators; permission_level=999"},
            {"X-Permissions": "*", "X-Access-Level": "root"},
        ]
        sensitive_words = [
            "admin", "all users", "delete", "manage", "settings", 
            "configuration", "user list", "permission", "root",
        ]
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for headers in role_payloads:
                try:
                    req_headers = {**base_request.get("headers", {})}
                    req_headers.update(headers)
                    resp = await client.get(base_request.get("url", ""), headers=req_headers)
                    body = resp.text.lower()
                    if resp.status_code == 200 and any(w in body for w in sensitive_words):
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title="Role Manipulation Susceptibility",
                            description=f"Server accepted role manipulation via {list(headers.keys())}",
                            evidence=f"Headers: {headers}\nStatus: {resp.status_code}",
                            remediation="Enforce role-based access control server-side. Validate roles from session, not from client requests.",
                            cwe="CWE-269",
                        ))
                        break
                except Exception:
                    continue
        return results


class ActiveAuthForcedBrowsingCheck(BaseCheck):
    name = "active_auth_forced_browsing"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        protected_paths = [
            "/admin", "/dashboard", "/settings", "/users", "/config",
            "/api/admin", "/api/users", "/api/config", "/.env", "/backup",
            "/admin/panel", "/admin/users", "/admin/settings", "/api/internal",
            "/api/v1/admin", "/restricted", "/private", "/internal",
        ]
        from urllib.parse import urlparse
        parsed = urlparse(base_request.get("url", ""))
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for path in protected_paths:
                try:
                    resp = await client.get(f"{base_url}{path}", headers=base_request.get("headers", {}))
                    if resp.status_code == 200:
                        body = resp.text.lower()
                        if any(x in body for x in ["login", "sign in", "401", "unauthorized", "forbidden"]):
                            continue
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title="Forced Browsing - Protected Path Accessible",
                            description=f"Protected path {path} returned 200 without authentication",
                            evidence=f"URL: {base_url}{path}\nStatus: {resp.status_code}\nSize: {len(resp.content)}",
                            remediation="Implement proper access controls. Protected paths should return 401/403 for unauthenticated users.",
                            cwe="CWE-425",
                        ))
                except Exception:
                    continue
        return results


class ActiveAuthParamTamperingCheck(BaseCheck):
    name = "active_auth_param_tampering"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        tamper_params = [
            {"disabled": "false", "is_active": "true", "verified": "1"},
            {"approved": "true", "confirmed": "1", "status": "active"},
            {"role": "admin", "access": "full", "level": "10"},
            {"bypass": "true", "skip_auth": "1", "nocheck": "1"},
            {"administrator": "true", "root": "1", "superuser": "yes"},
        ]
        for params in tamper_params:
            try:
                url = base_request.get("url", "")
                separator = "&" if "?" in url else "?"
                test_url = f"{url}{separator}{'&'.join(f'{k}={v}' for k, v in params.items())}"
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    resp = await client.get(test_url, headers=base_request.get("headers", {}))
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if any(x in body for x in ["welcome", "dashboard", "admin", "profile", "settings"]):
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title="Authentication Parameter Tampering",
                            description=f"Adding {params} changed access level",
                            evidence=f"Params: {params}\nStatus: {resp.status_code}",
                            remediation="Do not rely on client-provided parameters for authorization decisions. Use server-side session data.",
                            cwe="CWE-472",
                        ))
                        break
            except Exception:
                continue
        return results

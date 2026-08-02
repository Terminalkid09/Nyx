import copy
import json
import httpx
import urllib.parse
from modules.scanner.base_check import BaseCheck, CheckResult


class IdorCheck(BaseCheck):
    """
    Smart IDOR detection with JSON structure comparison.

    Strategy:
    1. Make the original request to get baseline response.
    2. For each numeric / UUID-like parameter, iterate a set of probe values.
    3. If the response is JSON, compare *structure* (keys/types) and *values*:
       - Same structure + 200 status + different values → high-confidence IDOR
       - Probe returns 200 but same data → not an IDOR (could be cached)
       - Probe returns 200 and data is *empty* or significantly shorter → possible auth bypass
    4. For non-JSON responses, fall back to content-size heuristic (kept as low-confidence).
    """

    name = "active_idor"

    # Values that differ enough from typical IDs that we can expect the server
    # to return either different data or an access-denied response.
    _INT_PROBES = [1, 2, 10, 100, 1000, 9999, 999999]
    _UUID_PROBE = "00000000-0000-0000-0000-000000000001"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results: list[CheckResult] = []

        # Identify interesting params: numeric or UUID-shaped values
        numeric_params = [p for p in target_params if self._is_numeric_or_uuid(base_request, p)]
        if not numeric_params:
            return results

        async with httpx.AsyncClient(verify=False, timeout=12) as client:
            for param in numeric_params:
                try:
                    # ── Baseline ───────────────────────────────────────────
                    original_resp = await client.request(
                        method=base_request.get("method", "GET"),
                        url=base_request["url"],
                        headers=base_request.get("headers", {}),
                        content=(base_request.get("content") or b""),
                    )
                    original_is_uuid = self._param_is_uuid(base_request, param)
                    probes = [self._UUID_PROBE] if original_is_uuid else self._INT_PROBES

                    original_json = self._try_parse_json(original_resp.text)
                    original_keys = self._json_schema(original_json) if original_json is not None else None

                    for probe_val in probes:
                        modified = self._inject_param(base_request, param, str(probe_val))
                        resp = await client.request(
                            method=modified.get("method", "GET"),
                            url=modified["url"],
                            headers=modified.get("headers", {}),
                            content=(modified.get("content") or b""),
                        )

                        if resp.status_code != 200:
                            continue

                        probe_json = self._try_parse_json(resp.text)
                        probe_keys = self._json_schema(probe_json) if probe_json is not None else None

                        if original_json is not None and probe_json is not None:
                            # ── JSON-aware comparison ──────────────────────
                            verdict = self._compare_json_responses(
                                original_json, original_keys,
                                probe_json, probe_keys,
                                param, probe_val,
                            )
                            if verdict:
                                results.append(verdict)
                                break
                        else:
                            # ── Size-based fallback ────────────────────────
                            orig_size = len(original_resp.content)
                            resp_size = len(resp.content)
                            if orig_size > 50 and abs(orig_size - resp_size) > 50:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="medium",
                                    title="Potential IDOR (size diff) — manual verification recommended",
                                    description=(
                                        f"Parameter '{param}' returns a response of different size "
                                        f"when modified (probe={probe_val})."
                                    ),
                                    evidence=(
                                        f"Probe value: {probe_val}\n"
                                        f"Original response size: {orig_size} bytes\n"
                                        f"Modified response size: {resp_size} bytes"
                                    ),
                                    remediation=(
                                        "Implement server-side access control checks on all "
                                        "object references. Do not rely on hidden or obfuscated IDs."
                                    ),
                                    cwe="CWE-639",
                                ))
                                break
                except Exception:
                    continue

        return results

    # ── JSON helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _try_parse_json(text: str) -> dict | list | None:
        try:
            return json.loads(text)
        except Exception:
            return None

    @staticmethod
    def _json_schema(obj, _depth: int = 0) -> dict:
        """Return a dict mapping key paths → types (max depth 3)."""
        schema: dict = {}
        if _depth > 3:
            return schema
        if isinstance(obj, dict):
            for k, v in obj.items():
                schema[k] = type(v).__name__
                if isinstance(v, (dict, list)):
                    for sk, st in IdorCheck._json_schema(v, _depth + 1).items():
                        schema[f"{k}.{sk}"] = st
        elif isinstance(obj, list) and obj:
            schema = IdorCheck._json_schema(obj[0], _depth + 1)
        return schema

    def _compare_json_responses(
        self,
        orig_obj, orig_keys: dict,
        probe_obj, probe_keys: dict,
        param: str, probe_val,
    ) -> CheckResult | None:
        """
        High-confidence IDOR: same schema, 200 status, but values differ.
        This means the server returned *another* resource instead of rejecting the request.
        """
        if orig_keys != probe_keys:
            # Schema mismatch → could be an error wrapper, not a clean resource swap
            return None

        # Values must differ and the probe response must not be empty
        if orig_obj == probe_obj:
            return None  # Same data — cached or same object

        if not probe_obj:
            return None  # Empty response

        return CheckResult(
            triggered=True,
            severity="high",
            title="IDOR — Unauthorised Object Access Detected",
            description=(
                f"Parameter '{param}' returned a different resource object when probed with "
                f"value `{probe_val}`. The response structure is identical but the content differs, "
                f"indicating successful cross-account data access without proper authorisation."
            ),
            evidence=(
                f"Probe value: {probe_val}\n"
                f"Original response (truncated): {json.dumps(orig_obj)[:300]}\n"
                f"Probe response (truncated): {json.dumps(probe_obj)[:300]}"
            ),
            remediation=(
                "Implement server-side authorisation: verify that the authenticated user "
                "owns or has explicit access to the requested resource *before* returning it. "
                "Use opaque, non-guessable identifiers (UUIDs v4) as an additional defence-in-depth measure."
            ),
            cwe="CWE-639",
        )

    # ── URL / param helpers ───────────────────────────────────────────────

    @staticmethod
    def _get_param_value(base: dict, param: str) -> str:
        parsed = urllib.parse.urlparse(base["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        return params.get(param, "")

    def _is_numeric_or_uuid(self, base: dict, param: str) -> bool:
        val = self._get_param_value(base, param)
        if val.isdigit():
            return True
        # Basic UUID detection
        import re
        return bool(re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            val, re.IGNORECASE,
        ))

    def _param_is_uuid(self, base: dict, param: str) -> bool:
        import re
        val = self._get_param_value(base, param)
        return bool(re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            val, re.IGNORECASE,
        ))

    @staticmethod
    def _inject_param(base: dict, param: str, value: str) -> dict:
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if param in params:
            params[param] = value
            req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req

"""Boolean-blind SQL injection detection via differential analysis.

Sends paired TRUE and FALSE payloads and compares:
  - Response size difference (>5% threshold)
  - Content hash changes (TRUE page includes extra data)
  - Status code divergence

This catches blind SQLi that error-based scanners miss — no visible error
message, just subtle response differences when the injected condition flips.
"""
import hashlib
import httpx
import re
from typing import Optional
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse, parse_qsl, urlencode

# Paired payloads: (TRUE, FALSE, operator)
BLIND_PAIRS: list[tuple[str, str, str]] = [
    ("1' AND '1'='1", "1' AND '1'='2", "string"),
    ("1 AND 1=1", "1 AND 1=2", "numeric"),
    ("1' OR '1'='1", "1' OR '1'='2", "string-or"),
    ("1 OR 1=1", "1 OR 1=2", "numeric-or"),
    ("1' AND 1=1--", "1' AND 1=2--", "string-comment"),
    ("1 AND 1=1--", "1 AND 1=2--", "numeric-comment"),
    ("1' AND SLEEP(0)='1", "1' AND SLEEP(0)='2", "string-equality"),
]

# Heuristic patterns that indicate successful boolean-based SQLi
# (extra rows in TRUE response leak into page content)
_EXTRA_DATA_PATTERNS = [
    re.compile(r"<tr[^>]*>", re.IGNORECASE),
    re.compile(r"<li[^>]*>", re.IGNORECASE),
    re.compile(r"<div[^>]*class[^>]*item[^>]*>", re.IGNORECASE),
    re.compile(r"<article[^>]*>", re.IGNORECASE),
]


class ActiveSqliBlindCheck(BaseCheck):
    """Boolean-blind SQL injection — differential analysis."""

    name = "active_sqli_blind"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results: list[CheckResult] = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for true_p, false_p, operator in BLIND_PAIRS:
                    try:
                        result = await self._test_pair(client, base_request, param, true_p, false_p, operator)
                        if result:
                            results.append(result)
                            break  # Found one blind vector, move to next param
                    except Exception:
                        continue
        return results

    async def _test_pair(
        self,
        client: httpx.AsyncClient,
        base: dict,
        param: str,
        true_payload: str,
        false_payload: str,
        operator: str,
    ) -> Optional[CheckResult]:
        # Send TRUE request
        true_req = self._inject_payload(base, param, true_payload)
        true_resp = await client.request(**true_req)

        # Send FALSE request
        false_req = self._inject_payload(base, param, false_payload)
        false_resp = await client.request(**false_req)

        # ── Analysis ──────────────────────────────────────────────────
        evidence_parts: list[str] = []

        # 1. Response size divergence (>5%)
        size_diff_pct = 0.0
        if false_resp.status_code == 200:
            f_len = len(false_resp.text or "")
            t_len = len(true_resp.text or "")
            if f_len > 0:
                size_diff_pct = abs(t_len - f_len) / f_len * 100.0
                if size_diff_pct > 5:
                    evidence_parts.append(
                        f"Size divergence: TRUE={t_len}B, FALSE={f_len}B ({size_diff_pct:.1f}%)"
                    )

        # 2. Content hash difference (TRUE page contains extra rows/data)
        t_hash = hashlib.md5((true_resp.text or "").encode()).hexdigest()
        f_hash = hashlib.md5((false_resp.text or "").encode()).hexdigest()
        hash_diff = t_hash != f_hash
        if hash_diff:
            # Check if TRUE response has extra list/table items
            t_extra = sum(1 for p in _EXTRA_DATA_PATTERNS if p.search(true_resp.text or ""))
            f_extra = sum(1 for p in _EXTRA_DATA_PATTERNS if p.search(false_resp.text or ""))
            if t_extra > f_extra:
                evidence_parts.append(
                    f"TRUE response contains {t_extra - f_extra} more data rows ({t_extra} vs {f_extra})"
                )

        # 3. Status code divergence
        if true_resp.status_code != false_resp.status_code:
            evidence_parts.append(
                f"Status divergence: TRUE={true_resp.status_code}, FALSE={false_resp.status_code}"
            )

        if evidence_parts:
            return CheckResult(
                triggered=True,
                severity="high",
                title=f"Boolean-blind SQL Injection ({operator})",
                description=(
                    f"Parameter '{param}' responds differently to TRUE vs FALSE "
                    f"SQL conditions — consistent with boolean-blind SQL injection."
                ),
                evidence="\n".join(evidence_parts),
                remediation=(
                    "Use parameterized queries / prepared statements. "
                    "Never concatenate user input into SQL."
                ),
                cwe="CWE-89",
            )

        return None

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        import copy
        req = copy.deepcopy(base)
        parsed = urlparse(req["url"])
        params = dict(parse_qsl(parsed.query))
        params[param] = payload
        req["url"] = parsed._replace(query=urlencode(params)).geturl()
        return req
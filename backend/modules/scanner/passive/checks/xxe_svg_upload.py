import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XxeSvgUploadCheck(BaseCheck):
    name = "xxe_svg_upload"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        ct = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
        if not body or "xml" not in ct and "svg" not in ct and "multipart" not in ct:
            return results
        patterns = [
            (r"<!DOCTYPE\s+svg\s+\[", "DOCTYPE in SVG with internal subset"),
            (r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']file://", "XXE in SVG: file read via SYSTEM entity"),
            (r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']http://", "XXE in SVG: HTTP SYSTEM entity"),
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM", "XXE in SVG: parameter entity"),
            (r"<svg[^>]*>.*<!ENTITY", "SVG with entity definition"),
            (r"xmlns:xlink\s*=\s*[\"']http://www\.w3\.org/1999/xlink[\"'][^>]*xlink:href\s*=\s*[\"']http", "SVG xlink:href to external URL"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XXE via SVG upload",
                    description=f"{desc}. SVG files can contain XML entities that access local files or internal services.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:500]}",
                    remediation="Disable external entity processing in XML parsers processing SVG uploads. Validate SVG content strictly.",
                    cwe="CWE-611",
                ))
                break
        return results

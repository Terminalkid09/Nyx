import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SmugglingChunkedParsingCheck(BaseCheck):
    name = "smuggling_chunked_parsing"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        te = headers_lower.get("transfer-encoding", "")
        if "chunked" in te.lower():
            body = event.get("request_body", "") or event.get("body", "") or ""
            if body:
                lines = body.split("\r\n")
                for i, line in enumerate(lines):
                    line_stripped = line.strip()
                    if line_stripped and line_stripped != "0":
                        try:
                            chunk_size = int(line_stripped, 16)
                            if chunk_size > 1000000:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="medium",
                                    title="Transfer-Encoding chunked parsing issues",
                                    description=f"Chunk size '{line_stripped}' ({chunk_size} bytes) is unusually large, potential chunk size manipulation attack.",
                                    evidence=f"Chunk size: {line_stripped} ({chunk_size} bytes)\nPosition: line {i + 1}",
                                    remediation="Validate chunk size values. Reject unreasonable chunk sizes to avoid request smuggling.",
                                    cwe="CWE-444",
                                ))
                                break
                        except ValueError:
                            pass
        return results

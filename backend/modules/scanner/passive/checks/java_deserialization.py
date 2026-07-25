import re
from modules.scanner.base_check import BaseCheck, CheckResult


class JavaDeserializationCheck(BaseCheck):
    name = "java_deserialization"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or ""
        url = event.get("url", "") or request_data.get("url", "")
        combined = f"{url} {body}"

        java_ser_patterns = [
            (r"aced0005", "Java serialization magic bytes (aced0005)"),
            (r"rO0AB", "Java serialized object (Base64: rO0AB)"),
            (r"\xac\xed\x00\x05", "Java serialization magic bytes (raw)"),
            (r"rO0ABXNy", "Java serialized object (Base64, common class)"),
        ]
        for pattern, desc in java_ser_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="critical",
                    title="Java deserialization detected",
                    description=f"{desc} found. Java deserialization of untrusted data can lead to remote code execution.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Do not deserialize untrusted Java objects. Use safe serialization formats like JSON. Implement allowlist deserialization if necessary.",
                    cwe="CWE-502",
                ))
                break
        return results

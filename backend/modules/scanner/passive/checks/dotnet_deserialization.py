import re
from modules.scanner.base_check import BaseCheck, CheckResult


class DotnetDeserializationCheck(BaseCheck):
    name = "dotnet_deserialization"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or ""
        headers = event.get("headers", {}) or {}
        response_body = event.get("response_body", "") or ""
        combined = f"{body} {response_body}"

        dotnet_patterns = [
            (r"__VIEWSTATE", ".NET ViewState parameter"),
            (r"__EVENTVALIDATION", ".NET EventValidation parameter"),
            (r"__EVENTTARGET", ".NET EventTarget parameter"),
            (r"__EVENTARGUMENT", ".NET EventArgument parameter"),
            (r"__VIEWSTATEGENERATOR", ".NET ViewStateGenerator parameter"),
            (r"<machineKey", ".NET machineKey configuration"),
            (r"validationKey=\".*?\"", ".NET validation key exposed"),
            (r"decryptionKey=\".*?\"", ".NET decryption key exposed"),
        ]
        for pattern, desc in dotnet_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title=".NET deserialization detected",
                    description=f"{desc} found. .NET deserialization of untrusted data can lead to remote code execution.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Do not deserialize untrusted .NET objects. Use BinaryMessageFormatter with allowlists. Validate ViewState MAC and encryption.",
                    cwe="CWE-502",
                ))
                break
        return results

import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscCsvInjectionCheck(BaseCheck):
    name = "misc_csv_injection"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        ct = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
        if "text/csv" not in ct and "application/csv" not in ct:
            return results
        formula_patterns = [
            (r"^=", "CSV formula injection (=)"),
            (r'^\+', "CSV formula injection (+)"),
            (r"^-", "CSV formula injection (-)"),
            (r"^@", "CSV formula injection (@)"),
            (r"^=HYPERLINK", "CSV HYPERLINK injection"),
            (r"^=CMD", "CSV CMD injection"),
            (r"^=EXEC", "CSV EXEC injection"),
            (r"^=DDE", "CSV DDE injection"),
        ]
        for line in body.split("\n"):
            line = line.strip()
            if not line:
                continue
            cells = line.split(",")
            for cell in cells:
                cell = cell.strip().strip('"')
                for pattern, desc in formula_patterns:
                    if re.match(pattern, cell):
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="CSV injection via formula injection",
                            description=f"{desc} detected in CSV output. CSV formulas can execute arbitrary commands when opened in spreadsheet applications.",
                            evidence=f"Cell value: {cell[:100]}\nContent-Type: {ct}",
                            remediation="Sanitize CSV output by prefixing formula characters (=, +, -, @) with a single quote or space.",
                            cwe="CWE-1236",
                        ))
                        break
                if results:
                    break
            if results:
                break
        return results

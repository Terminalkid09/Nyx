import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

PATHS = ['/swagger.json', '/swagger.yaml', '/openapi.json', '/api/docs', '/api/swagger', '/swagger-ui.html', '/v2/api-docs', '/v3/api-docs']
ERROR_PATTERNS = [
    (r'"openapi"|"swagger"|"info".*"version"|"paths"', 'OpenAPI/Swagger spec detected'),
    (r'swagger-ui|Swagger UI', 'Swagger UI detected'),
]


class ActiveSwaggerExposedCheck(BaseCheck):
    name = "active_swagger_exposed"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for path in PATHS:
                try:
                    req = dict(base_request)
                    parsed = urlparse(req.get("url", ""))
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    resp = await client.get(f"{base_url}{path}", headers=req.get("headers", {}))
                    for pattern, desc in ERROR_PATTERNS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title="Swagger/OpenAPI Documentation Exposed",
                                description=f"{desc}. Swagger UI or OpenAPI specification files are publicly accessible.",
                                evidence=f"Path: {path}\nPattern: {pattern}",
                                remediation="Restrict access to API documentation in production. Use authentication for documentation endpoints.",
                                cwe="CWE-200",
                            ))
                            break
                except Exception:
                    continue
        return results

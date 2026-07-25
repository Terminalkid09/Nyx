import re
from modules.scanner.base_check import BaseCheck, CheckResult

COMMON_OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/api/docs",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v3/openapi.json",
    "/api/openapi.json",
    "/swagger-ui/",
    "/api/swagger/",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/docs/",
    "/api/doc",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
    "/api/v1/swagger.json",
    "/api-docs",
    "/api/swagger-ui/",
]


class OpenApiExposureCheck(BaseCheck):
    name = "openapi_exposure"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", "")).lower()
        body = event.get("body", "") or ""
        status = event.get("status")
        content_type = (event.get("headers", {}) or {}).get("content-type", "")

        for candidate in COMMON_OPENAPI_PATHS:
            if path.endswith(candidate) or path.endswith(candidate.rstrip("/")):
                title = f"Potential OpenAPI/Swagger documentation exposed"
                severity = "low"
                cwe = "CWE-200"

                if status == 200 and body:
                    if '"openapi"' in body or '"swagger"' in body or '"info"' in body:
                        severity = "medium"
                        title = "OpenAPI/Swagger documentation exposed"

                results.append(CheckResult(
                    triggered=True,
                    severity=severity,
                    title=title,
                    description=f"API documentation may be exposed at {path}.",
                    evidence=f"URL: {path}\nStatus: {status}\nContent-Type: {content_type}",
                    remediation="Restrict access to API documentation in production. Use authentication or network restrictions.",
                    cwe=cwe,
                ))
                break

        if not results and status == 200:
            openapi_content_patterns = [
                r'"openapi"\s*:\s*"[0-9]',
                r'"swagger"\s*:\s*"[0-9]',
                r'"info"\s*:\s*\{[^}]*"title"',
                r'"paths"\s*:\s*\{[^}]*"get"',
                r'"\/api\/"',
            ]
            for pattern in openapi_content_patterns:
                if re.search(pattern, body):
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title="OpenAPI/Swagger content detected in response",
                        description=f"Response body at {path} appears to contain OpenAPI or Swagger specification content.",
                        evidence=f"URL: {path}\nPattern matched: {pattern}",
                        remediation="Ensure API specification files are not publicly accessible.",
                        cwe="CWE-200",
                    ))
                    break

        return results

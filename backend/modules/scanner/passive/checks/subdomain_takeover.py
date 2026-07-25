import re
from modules.scanner.base_check import BaseCheck, CheckResult

TAKEOVER_SIGNATURES = [
    {
        "service": "AWS S3",
        "patterns": [
            r"NoSuchBucket",
            r"The specified bucket does not exist",
            r"<Code>NoSuchBucket</Code>",
            r"AllAccessDisabled",
        ],
        "cwe": "CWE-345",
    },
    {
        "service": "Azure",
        "patterns": [
            r"404 Not Found",
            r"ResourceNotFound",
            r"The specified resource does not exist",
        ],
        "cwe": "CWE-345",
    },
    {
        "service": "GitHub Pages",
        "patterns": [
            r"There isn't a GitHub Pages site here",
            r"Repository not found",
            r"Page not found",
        ],
        "cwe": "CWE-345",
    },
    {
        "service": "Heroku",
        "patterns": [
            r"No such app",
            r"There's nothing here, yet",
            r"Heroku | No such app",
        ],
        "cwe": "CWE-345",
    },
    {
        "service": "Shopify",
        "patterns": [
            r"Sorry, this shop is currently unavailable",
            r"Only one step left",
        ],
        "cwe": "CWE-345",
    },
    {
        "service": "CloudFront",
        "patterns": [
            r"BadRequest",
            r"The CNAME you provided does not exist",
            r"CloudFront: The CNAME you provided is already associated with a different resource",
        ],
        "cwe": "CWE-345",
    },
    {
        "service": "Fastly",
        "patterns": [
            r"Fastly error: unknown domain",
            r"Please check that this domain has been added to a service",
        ],
        "cwe": "CWE-345",
    },
    {
        "service": "Pantheon",
        "patterns": [
            r"The site you are looking for could not be found",
            r"404 error unknown site",
        ],
        "cwe": "CWE-345",
    },
    {
        "service": "WordPress",
        "patterns": [
            r"Domain not mapped",
            r"User does not exist",
        ],
        "cwe": "CWE-345",
    },
    {
        "service": "Tumblr",
        "patterns": [
            r"There's nothing here",
            r"Whatever you were looking for doesn't currently exist at this address",
        ],
        "cwe": "CWE-345",
    },
    {
        "service": "Unbounce",
        "patterns": [
            r"The page you requested was not found",
            r"doesn't exist",
        ],
        "cwe": "CWE-345",
    },
    {
        "service": "Readme.io",
        "patterns": [
            r"Project doesnt exist... yet",
            r"<title>ReadMe</title>",
        ],
        "cwe": "CWE-345",
    },
    {
        "service": "Strikingly",
        "patterns": [
            r"The page you're looking for has moved or been deleted",
        ],
        "cwe": "CWE-345",
    },
]

CNAME_PATTERN = re.compile(
    r"(?:CNAME\s+|alias\s+|cname\s*=?\s*)([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})",
    re.IGNORECASE
)


class SubdomainTakeoverCheck(BaseCheck):
    name = "subdomain_takeover"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("body", "") or ""
        status = event.get("status")
        content_type = (event.get("headers", {}) or {}).get("content-type", "")

        for sig in TAKEOVER_SIGNATURES:
            for pattern in sig["patterns"]:
                if re.search(pattern, body, re.IGNORECASE):
                    url = request_data.get("url", request_data.get("path", ""))
                    results.append(CheckResult(
                        triggered=True,
                        severity="high",
                        title=f"Subdomain takeover possible - {sig['service']}",
                        description=f"Response matches {sig['service']} unclaimed page signature, suggesting a possible subdomain takeover.",
                        evidence=f"URL: {url}\nStatus: {status}\nMatched: {pattern}",
                        remediation=f"Remove DNS CNAME record pointing to {sig['service']} or claim the resource. Regularly audit DNS records for dangling references.",
                        cwe=sig["cwe"],
                    ))
                    break

        return results

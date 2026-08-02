CWE_CVSS_MAPPING = {
    "CWE-89":  {"score": 9.8, "severity": "critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "name": "SQL Injection"},
    "CWE-78":  {"score": 9.8, "severity": "critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "name": "OS Command Injection"},
    "CWE-94":  {"score": 9.8, "severity": "critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "name": "Server-Side Template Injection"},
    "CWE-502": {"score": 9.8, "severity": "critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "name": "Insecure Deserialization"},
    "CWE-434": {"score": 9.8, "severity": "critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "name": "Unrestricted File Upload"},
    "CWE-22":  {"score": 7.5, "severity": "high",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "name": "Path Traversal"},
    "CWE-918": {"score": 8.6, "severity": "high",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "name": "Server-Side Request Forgery (SSRF)"},
    "CWE-611": {"score": 7.5, "severity": "high",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "name": "XML External Entity (XXE)"},
    "CWE-79":  {"score": 6.1, "severity": "medium",   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "name": "Cross-Site Scripting (XSS)"},
    "CWE-352": {"score": 8.8, "severity": "high",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "name": "Cross-Site Request Forgery (CSRF)"},
    "CWE-601": {"score": 6.1, "severity": "medium",   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "name": "Open Redirect"},
    "CWE-306": {"score": 9.1, "severity": "critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "name": "Missing Authentication"},
    "CWE-639": {"score": 7.5, "severity": "high",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "name": "Insecure Direct Object Reference (IDOR)"},
    "CWE-1321": {"score": 9.8, "severity": "critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "name": "Prototype Pollution"},
    "CWE-444": {"score": 7.5, "severity": "high",     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", "name": "HTTP Request Smuggling"},
    "CWE-16":  {"score": 5.3, "severity": "medium",   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "name": "Security Misconfiguration"},
    "CWE-200": {"score": 5.3, "severity": "medium",   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "name": "Information Exposure"},
}

def get_cvss_for_cwe(cwe_id: str) -> dict:
    return CWE_CVSS_MAPPING.get(cwe_id, {
        "score": 0.0,
        "severity": "info",
        "vector": "",
        "name": "Unknown Vulnerability"
    })

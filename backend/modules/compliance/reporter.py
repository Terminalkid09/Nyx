"""Compliance report generator — OWASP Top 10, PCI-DSS, GDPR, NIS2, ISO 27001.

Scans the findings database and maps each finding to the applicable
compliance framework(s). Generates a structured JSON report that can
be exported or rendered as HTML/Markdown.

Frameworks supported:
  - OWASP Top 10 2021
  - PCI-DSS v4.0 (requirement-level mapping)
  - GDPR Art. 32 (security of processing)
  - NIS2 (Directive (EU) 2022/2555) Art. 21(2) measures
  - ISO/IEC 27001:2022 Annex A controls

Every mapping is technical evidence from the findings, never a certification:
measures a web assessment cannot observe are reported as NOT_ASSESSED.
No external dependencies beyond what's already in the project.
"""
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from core.storage.models import Finding, SeverityEnum


# ── Mapping tables ──────────────────────────────────────────────────────────
# Each category has a list of (compiled_regex, priority) tuples. Higher
# priority wins when a finding matches multiple categories. The CWE-to-OWASP
# mapping (cwe_map) is checked first because it's the most reliable signal.

# CWE prefix → OWASP category (exact, no regex needed)
_CWE_TO_OWASP: dict[str, str] = {
    "CWE-22": "A01:2021", "CWE-23": "A01:2021", "CWE-35": "A01:2021",
    "CWE-59": "A01:2021", "CWE-200": "A01:2021", "CWE-201": "A01:2021",
    "CWE-219": "A01:2021", "CWE-264": "A01:2021", "CWE-275": "A01:2021",
    "CWE-276": "A01:2021", "CWE-284": "A01:2021", "CWE-285": "A01:2021",
    "CWE-352": "A04:2021",  # CSRF → Insecure Design
    "CWE-639": "A01:2021", "CWE-862": "A01:2021", "CWE-863": "A01:2021",

    "CWE-89": "A03:2021",   # SQL Injection
    "CWE-79": "A03:2021",   # XSS
    "CWE-78": "A03:2021",   # Command Injection
    "CWE-94": "A03:2021",   # Code Injection
    "CWE-91": "A03:2021",   # XML/XPATH Injection
    "CWE-611": "A03:2021",  # XXE
    "CWE-918": "A10:2021",  # SSRF

    "CWE-310": "A02:2021", "CWE-311": "A02:2021", "CWE-312": "A02:2021",
    "CWE-319": "A02:2021", "CWE-326": "A02:2021", "CWE-327": "A02:2021",
    "CWE-328": "A02:2021", "CWE-347": "A02:2021",

    "CWE-307": "A07:2021", "CWE-287": "A07:2021", "CWE-522": "A07:2021",
    "CWE-384": "A07:2021", "CWE-521": "A07:2021",

    "CWE-502": "A08:2021",  # Insecure Deserialization
    "CWE-494": "A08:2021",  # Download of Code Without Integrity Check

    "CWE-117": "A09:2021", "CWE-532": "A09:2021", "CWE-778": "A09:2021",
    "CWE-807": "A01:2021",
}

# Regex-based keyword matchers (compiled once). Each tuple is (re.Pattern, priority).
# Priority 1 = CWE (best), 2 = exact keyword, 3 = fuzzy substring.
OWASP_TOP10_2021 = {
    "A01:2021": {
        "title": "Broken Access Control",
        "patterns": [
            (re.compile(r"\bidor\b", re.IGNORECASE), 2),
            (re.compile(r"\baccess[.\s_-]*control\b(?![-.\s]*allow|[-.\s]*origin)", re.IGNORECASE), 2),
            (re.compile(r"\bdirectory[.\s_-]*traversal\b", re.IGNORECASE), 2),
            (re.compile(r"\bpath[.\s_-]*traversal\b", re.IGNORECASE), 2),
            (re.compile(r"\bprivilege[.\s_-]*escalation\b", re.IGNORECASE), 2),
            (re.compile(r"\bunauthorized\b", re.IGNORECASE), 3),
            (re.compile(r"\bforbidden\b", re.IGNORECASE), 3),
        ],
    },
    "A02:2021": {
        "title": "Cryptographic Failures",
        "patterns": [
            (re.compile(r"\bcrypto\b", re.IGNORECASE), 2),
            (re.compile(r"\bweak[.\s_-]*crypto\b", re.IGNORECASE), 2),
            (re.compile(r"\bplaintext\b", re.IGNORECASE), 3),
            (re.compile(r"\bcleartext\b", re.IGNORECASE), 3),
            (re.compile(r"\bunencrypted\b", re.IGNORECASE), 3),
            (re.compile(r"\bplain[.\s_-]*text\b", re.IGNORECASE), 3),
        ],
    },
    "A03:2021": {
        "title": "Injection",
        "patterns": [
            (re.compile(r"\bsql[.\s_-]*injection\b|\bsqli\b", re.IGNORECASE), 2),
            (re.compile(r"\bcross[.\s_-]*site[.\s_-]*scripting\b|\bxss\b", re.IGNORECASE), 2),
            (re.compile(r"\bcommand[.\s_-]*injection\b", re.IGNORECASE), 2),
            (re.compile(r"\bssti\b|\bserver[.\s_-]*side[.\s_-]*template", re.IGNORECASE), 2),
            (re.compile(r"\bxxe\b|\bxml[.\s_-]*external[.\s_-]*entity", re.IGNORECASE), 2),
            (re.compile(r"\bxpath[.\s_-]*injection\b", re.IGNORECASE), 2),
            (re.compile(r"\bldap[.\s_-]*injection\b", re.IGNORECASE), 2),
            (re.compile(r"\binjection\b", re.IGNORECASE), 3),
        ],
    },
    "A04:2021": {
        "title": "Insecure Design",
        "patterns": [
            (re.compile(r"\bcsrf\b|\bcross[.\s_-]*site[.\s_-]*request[.\s_-]*forgery\b", re.IGNORECASE), 2),
            (re.compile(r"\blogic[.\s_-]*flaw\b", re.IGNORECASE), 2),
            (re.compile(r"\binsecure[.\s_-]*design\b", re.IGNORECASE), 2),
            (re.compile(r"\brace[.\s_-]*condition\b", re.IGNORECASE), 3),
            (re.compile(r"\btoctou\b", re.IGNORECASE), 3),
        ],
    },
    "A05:2021": {
        "title": "Security Misconfiguration",
        "patterns": [
            (re.compile(r"\bcors[.\s_-]*misconfig", re.IGNORECASE), 2),  # e.g. "CORS misconfiguration"
            (re.compile(r"\bcsp[.\s_-]*bypass", re.IGNORECASE), 2),
            (re.compile(r"\bmisconfigur", re.IGNORECASE), 2),
            (re.compile(r"\bdirectory[.\s_-]*listing", re.IGNORECASE), 2),
            (re.compile(r"\bdebug[.\s_-]*mode", re.IGNORECASE), 2),
            (re.compile(r"\bsensitive[.\s_-]*file", re.IGNORECASE), 2),
            (re.compile(r"\bdefault[.\s_-]*credential", re.IGNORECASE), 2),
            (re.compile(r"\bexposed\b", re.IGNORECASE), 3),
            (re.compile(r"\bdisclosure\b", re.IGNORECASE), 3),
        ],
    },
    "A06:2021": {
        "title": "Vulnerable and Outdated Components",
        "patterns": [
            (re.compile(r"\boutdated[.\s_-]*component\b", re.IGNORECASE), 2),
            (re.compile(r"\bversion[.\s_-]*disclosure\b", re.IGNORECASE), 2),
            (re.compile(r"\bknown[.\s_-]*vulnerab", re.IGNORECASE), 3),
            (re.compile(r"\bdeprecated\b", re.IGNORECASE), 3),
        ],
    },
    "A07:2021": {
        "title": "Identification and Authentication Failures",
        "patterns": [
            (re.compile(r"\bauth[.\s_-]*bypass\b", re.IGNORECASE), 2),
            (re.compile(r"\bsession[.\s_-]*fixation\b", re.IGNORECASE), 2),
            (re.compile(r"\bweak[.\s_-]*password\b", re.IGNORECASE), 2),
            (re.compile(r"\bmissing[.\s_-]*auth\b", re.IGNORECASE), 2),
            (re.compile(r"\bbrute[.\s_-]*force\b", re.IGNORECASE), 3),
            (re.compile(r"\bcredential[.\s_-]*stuffing\b", re.IGNORECASE), 3),
        ],
    },
    "A08:2021": {
        "title": "Software and Data Integrity Failures",
        "patterns": [
            (re.compile(r"\binsecure[.\s_-]*deserial", re.IGNORECASE), 2),
            (re.compile(r"\bintegrity[.\s_-]*failure\b", re.IGNORECASE), 2),
            (re.compile(r"\bdeserializ", re.IGNORECASE), 3),
        ],
    },
    "A09:2021": {
        "title": "Security Logging and Monitoring Failures",
        "patterns": [
            (re.compile(r"\blogging[.\s_-]*failure\b", re.IGNORECASE), 2),
            (re.compile(r"\blog[.\s_-]*injection\b", re.IGNORECASE), 2),
            (re.compile(r"\binsufficient[.\s_-]*log", re.IGNORECASE), 3),
        ],
    },
    "A10:2021": {
        "title": "Server-Side Request Forgery (SSRF)",
        "patterns": [
            (re.compile(r"\bssrf\b", re.IGNORECASE), 2),
            (re.compile(r"\bserver[.\s_-]*side[.\s_-]*request[.\s_-]*forgery\b", re.IGNORECASE), 2),
        ],
    },
}

PCI_DSS_REQUIREMENTS = {
    "6.2.4": {"title": "Insecure web application development", "owasp_match": ["A03:2021", "A05:2021"]},
    "6.4.1": {"title": "Protect public-facing web apps from attacks", "owasp_match": ["A03:2021", "A04:2021"]},
    "8.3":   {"title": "MFA for administrative access", "owasp_match": ["A07:2021"]},
    "10.2":  {"title": "Audit trail for all access", "owasp_match": ["A09:2021"]},
    "11.3":  {"title": "External and internal vulnerability scans", "owasp_match": []},
    "12.3.3": {"title": "Compliance confirmation", "owasp_match": []},
}

GDPR_ARTICLES = {
    "Art.32": {"title": "Security of processing", "owasp_match": ["A02:2021", "A05:2021"]},
    "Art.33": {"title": "Notification of breach to supervisory authority", "owasp_match": ["A09:2021"]},
}

# NIS2, Directive (EU) 2022/2555, Art. 21(2) measures (a)-(j).
#
# ``assessed: False`` marks a measure a scanner cannot evidence: no amount of
# findings proves a risk-analysis policy exists. Those come back as
# NOT_ASSESSED instead of a dishonest PASS.
NIS2_MEASURES = {
    "21.2.a": {
        "title": "Risk analysis and information system security policies",
        "owasp_match": [],
        "assessed": False,
    },
    "21.2.b": {"title": "Incident handling", "owasp_match": ["A09:2021"], "assessed": True},
    "21.2.c": {
        "title": "Business continuity, backup management and disaster recovery",
        "owasp_match": [],
        "assessed": False,
    },
    "21.2.d": {"title": "Supply chain security", "owasp_match": ["A08:2021"], "assessed": True},
    "21.2.e": {
        "title": "Security in acquisition, development and maintenance (vulnerability handling)",
        "owasp_match": ["A03:2021", "A06:2021"],
        "assessed": True,
    },
    "21.2.f": {
        "title": "Policies to assess the effectiveness of security measures",
        "owasp_match": [],
        "assessed": False,
    },
    "21.2.g": {
        "title": "Cyber hygiene practices and cybersecurity training",
        "owasp_match": [],
        "assessed": False,
    },
    "21.2.h": {
        "title": "Cryptography and, where appropriate, encryption",
        "owasp_match": ["A02:2021"],
        "assessed": True,
    },
    "21.2.i": {
        "title": "Human resources security, access control policies and asset management",
        "owasp_match": ["A01:2021", "A07:2021"],
        "assessed": True,
    },
    "21.2.j": {
        "title": "Multi-factor authentication and secure communications",
        "owasp_match": ["A07:2021"],
        "assessed": True,
    },
}

# ISO/IEC 27001:2022 Annex A controls a web assessment can actually evidence.
ISO_27001_CONTROLS = {
    "5.7":  {"title": "Threat intelligence", "owasp_match": [], "assessed": False},
    "5.15": {"title": "Access control", "owasp_match": ["A01:2021"], "assessed": True},
    "5.17": {"title": "Authentication information", "owasp_match": ["A07:2021"], "assessed": True},
    "8.2":  {"title": "Privileged access rights", "owasp_match": ["A01:2021"], "assessed": True},
    "8.8":  {"title": "Management of technical vulnerabilities", "owasp_match": ["A06:2021"], "assessed": True},
    "8.9":  {"title": "Configuration management", "owasp_match": ["A05:2021"], "assessed": True},
    "8.12": {"title": "Data leakage prevention", "owasp_match": ["A01:2021"], "assessed": True},
    "8.16": {"title": "Monitoring activities", "owasp_match": ["A09:2021"], "assessed": True},
    "8.20": {"title": "Networks security", "owasp_match": ["A10:2021"], "assessed": True},
    "8.24": {"title": "Use of cryptography", "owasp_match": ["A02:2021"], "assessed": True},
    "8.26": {"title": "Application security requirements", "owasp_match": ["A03:2021", "A04:2021"], "assessed": True},
    "8.28": {"title": "Secure coding", "owasp_match": ["A03:2021"], "assessed": True},
}

NIS2_SCOPE = {
    "basis": "Directive (EU) 2022/2555, Art. 21(2), measures (a)-(j)",
    "caveat": (
        "Technical evidence only: each measure is mapped from the findings of "
        "this engagement. A measure without findings says nothing about the "
        "operator's policy, training or continuity plans, so it is reported "
        "as NOT_ASSESSED rather than PASS."
    ),
}

ISO_27001_SCOPE = {
    "basis": "ISO/IEC 27001:2022, Annex A controls evidenced from findings",
    "caveat": (
        "Technical evidence only. Annex A includes people and physical "
        "controls a web assessment cannot observe; a nonconformity (NC) "
        "and its risk acceptance are the auditor's determination, not this "
        "report's."
    ),
}


# ── Report generation ───────────────────────────────────────────────────────

class ComplianceReportGenerator:
    """Generate compliance reports from findings in the database."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._findings: list[dict] | None = None

    async def _load_findings(self) -> list[dict]:
        if self._findings is not None:
            return self._findings
        # Dismissed findings must not count against a control: a false positive
        # reported as a PCI failure is worse than no report at all. The
        # operator's severity override travels too, so a re-rated finding is
        # counted at the severity the assessor decided.
        result = await self.db.execute(
            select(Finding).where(Finding.triage_status != "false_positive")
        )
        rows = result.scalars().all()
        self._findings = [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": (
                    f.severity_override
                    if f.severity_override in ("critical", "high", "medium", "low", "info")
                    else (f.severity.value if hasattr(f.severity, "value") else str(f.severity))
                ),
                "cwe": getattr(f, "cwe", None),
                "description": getattr(f, "description", "") or "",
                "host": getattr(f, "host", "") or "",
                "path": getattr(f, "path", "") or "",
                "cvss_score": getattr(f, "cvss_score", None),
            }
            for f in rows
        ]
        return self._findings

    def _findings_to_owasp(self, findings: list[dict]) -> dict[str, list[dict]]:
        """Map findings to OWASP Top 10 2021 using CWE priority + regex.

        Algorithm:
          1. CWE match → instant assignment (highest confidence, priority 1)
          2. Regex keyword match → best (priority 2) or fuzzy (priority 3)
          3. Unmatched → A05:2021 (Misconfiguration) as safe fallback

        A single finding goes into at most ONE OWASP category (the highest-
        confidence match). This avoids double-counting findings across
        categories — a SQLi finding is A03, not A03 AND A05.
        """
        categories: dict[str, list[dict]] = {k: [] for k in OWASP_TOP10_2021}

        for f in findings:
            best_category: str | None = None
            best_priority = 999  # lower = better

            # ── Step 1: CWE lookup (priority 1) ─────────────────────────
            cwe = (f.get("cwe") or "").upper().strip()
            if cwe and cwe in _CWE_TO_OWASP:
                best_category = _CWE_TO_OWASP[cwe]
                best_priority = 1

            # ── Step 2: Regex keyword scanning (priorities 2-3) ────────
            f_str = f"{f['title']} {f.get('description', '')}"
            for owasp_id, meta in OWASP_TOP10_2021.items():
                for pattern, pri in meta["patterns"]:
                    if pri >= best_priority:
                        continue  # already have a better match
                    if pattern.search(f_str):
                        best_category = owasp_id
                        best_priority = pri
                        break  # break inner loop, keep scanning categories

            # ── Step 3: Assign ──────────────────────────────────────────
            if best_category:
                categories[best_category].append(f)
            else:
                categories["A05:2021"].append(f)

        return categories

    async def generate_owasp_report(self) -> dict:
        """Generate OWASP Top 10 2021 compliance report."""
        findings = await self._load_findings()
        mapped = self._findings_to_owasp(findings)

        total = len(findings)
        severity_counts = {}
        for f in findings:
            s = f["severity"]
            severity_counts[s] = severity_counts.get(s, 0) + 1

        categories = []
        for owasp_id, meta in OWASP_TOP10_2021.items():
            cat_findings = mapped[owasp_id]
            categories.append({
                "id": owasp_id,
                "title": meta["title"],
                "finding_count": len(cat_findings),
                "finding_ids": [f["id"] for f in cat_findings],
                "findings": cat_findings,
                "pass": len(cat_findings) == 0,
            })

        return {
            "report_id": str(uuid.uuid4()),
            "framework": "OWASP Top 10 2021",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": total,
                "severity_breakdown": severity_counts,
                "categories_with_findings": sum(1 for c in categories if c["finding_count"] > 0),
                "categories_clean": sum(1 for c in categories if c["pass"]),
            },
            "categories": categories,
        }

    async def generate_pci_dss_report(self) -> dict:
        """Generate PCI-DSS v4.0 compliance report."""
        findings = await self._load_findings()
        owasp_mapped = self._findings_to_owasp(findings)

        results = []
        for req_id, meta in PCI_DSS_REQUIREMENTS.items():
            violations: list[dict] = []
            for owasp_id in meta["owasp_match"]:
                violations.extend(owasp_mapped.get(owasp_id, []))
            results.append({
                "requirement_id": req_id,
                "title": meta["title"],
                "status": "FAIL" if violations else "PASS",
                "violations": violations,
                "violation_count": len(violations),
            })

        return {
            "report_id": str(uuid.uuid4()),
            "framework": "PCI-DSS v4.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_requirements": len(results),
                "passed": sum(1 for r in results if r["status"] == "PASS"),
                "failed": sum(1 for r in results if r["status"] == "FAIL"),
                "total_violations": sum(r["violation_count"] for r in results),
            },
            "requirements": results,
        }

    async def generate_gdpr_report(self) -> dict:
        """Generate GDPR Art. 32 security-of-processing report."""
        findings = await self._load_findings()
        owasp_mapped = self._findings_to_owasp(findings)

        articles = []
        for art_id, meta in GDPR_ARTICLES.items():
            violations: list[dict] = []
            for owasp_id in meta["owasp_match"]:
                violations.extend(owasp_mapped.get(owasp_id, []))
            articles.append({
                "article": art_id,
                "title": meta["title"],
                "status": "FAIL" if violations else "PASS",
                "violations": violations,
                "violation_count": len(violations),
            })

        return {
            "report_id": str(uuid.uuid4()),
            "framework": "GDPR Art. 32",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_articles": len(articles),
                "passed": sum(1 for a in articles if a["status"] == "PASS"),
                "failed": sum(1 for a in articles if a["status"] == "FAIL"),
                "total_violations": sum(a["violation_count"] for a in articles),
            },
            "articles": articles,
        }

    async def _generate_measure_report(
        self,
        framework: str,
        table: dict[str, dict],
        id_key: str,
        list_key: str,
        scope: dict,
    ) -> dict:
        """Shared shape for the requirement/control style frameworks.

        ``PASS`` means "assessed and clean", ``FAIL`` means findings landed in
        the mapped OWASP categories, and ``NOT_ASSESSED`` means this engagement
        produced no evidence either way.
        """
        findings = await self._load_findings()
        owasp_mapped = self._findings_to_owasp(findings)

        entries: list[dict] = []
        for entry_id, meta in table.items():
            violations: list[dict] = []
            for owasp_id in meta["owasp_match"]:
                violations.extend(owasp_mapped.get(owasp_id, []))
            if violations:
                status = "FAIL"
            elif meta["assessed"]:
                status = "PASS"
            else:
                status = "NOT_ASSESSED"
            entries.append(
                {
                    id_key: entry_id,
                    "title": meta["title"],
                    "status": status,
                    "violations": violations,
                    "violation_count": len(violations),
                }
            )

        return {
            "report_id": str(uuid.uuid4()),
            "framework": framework,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": scope,
            "summary": {
                "total": len(entries),
                "passed": sum(1 for e in entries if e["status"] == "PASS"),
                "failed": sum(1 for e in entries if e["status"] == "FAIL"),
                "not_assessed": sum(1 for e in entries if e["status"] == "NOT_ASSESSED"),
                "total_violations": sum(e["violation_count"] for e in entries),
            },
            list_key: entries,
        }

    async def generate_nis2_report(self) -> dict:
        """Generate a NIS2 Art. 21(2) measures report."""
        return await self._generate_measure_report(
            framework="NIS2 Art. 21(2)",
            table=NIS2_MEASURES,
            id_key="measure_id",
            list_key="measures",
            scope=NIS2_SCOPE,
        )

    async def generate_iso27001_report(self) -> dict:
        """Generate an ISO/IEC 27001:2022 Annex A controls report."""
        return await self._generate_measure_report(
            framework="ISO/IEC 27001:2022 Annex A",
            table=ISO_27001_CONTROLS,
            id_key="control_id",
            list_key="controls",
            scope=ISO_27001_SCOPE,
        )

    async def generate_full_report(self) -> dict:
        """Generate all compliance reports in one call."""
        return {
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings_total": len(await self._load_findings()),
            "owasp": await self.generate_owasp_report(),
            "pci_dss": await self.generate_pci_dss_report(),
            "gdpr": await self.generate_gdpr_report(),
            "nis2": await self.generate_nis2_report(),
            "iso27001": await self.generate_iso27001_report(),
        }
"""BUG-02: dedupe must keep one finding per weakness and parameter."""
from modules.scanner.active.scanner import remember_finding
from modules.scanner.base_check import CheckResult


def _finding(param: str | None, title: str = "SQL Injection detected (MySQL)"):
    return CheckResult(
        triggered=True, severity="high", title=title,
        description="", cwe="CWE-89", param=param,
    )


def test_same_param_payload_variants_collapse():
    seen: set = set()
    assert remember_finding(_finding("id"), seen) is True
    assert remember_finding(_finding("id"), seen) is False


def test_different_params_are_distinct():
    seen: set = set()
    assert remember_finding(_finding("id"), seen) is True
    assert remember_finding(_finding("user_id"), seen) is True
    assert len(seen) == 2


def test_missing_param_still_dedupes_by_cwe_and_title():
    seen: set = set()
    assert remember_finding(_finding(None), seen) is True
    assert remember_finding(_finding(None), seen) is False


def test_payload_variants_from_different_checks_collapse():
    # active_xss, active_xss_variants and active_xss_context all report CWE-79
    # for the same parameter with different titles: one finding, not three.
    seen: set = set()
    assert remember_finding(_finding("q", "Reflected XSS detected"), seen) is True
    assert remember_finding(_finding("q", "Reflected XSS variant detected"), seen) is False
    assert remember_finding(
        _finding("q", "Reflected XSS (context: text_node)"), seen
    ) is False


def test_checks_without_cwe_still_dedupe_by_title():
    seen: set = set()
    plain = CheckResult(triggered=True, title="Header missing", param="q")
    assert remember_finding(plain, seen) is True
    assert remember_finding(plain, seen) is False

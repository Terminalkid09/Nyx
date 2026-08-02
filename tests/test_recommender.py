"""Tests for the recommendation engine."""
import uuid
from datetime import datetime, timezone
from core.events.bus import EventBus
from core.recommender.engine import RecommendationEngine, RECOMMENDATION_RULES


def _make_event(cwe: str, severity: str = "medium", title: str = "Test finding") -> dict:
    return {
        "type": "finding.created",
        "id": str(uuid.uuid4()),
        "cwe": cwe,
        "severity": severity,
        "title": title,
        "module": "test_scanner",
        "session_id": str(uuid.uuid4()),
        "request_id": str(uuid.uuid4()),
    }


def test_engine_initializes():
    bus = EventBus()
    engine = RecommendationEngine(bus)
    assert engine is not None
    stats = engine.get_stats()
    assert stats["total"] == 0


def test_sqli_finding_generates_recommendations():
    bus = EventBus()
    engine = RecommendationEngine(bus)

    import asyncio
    asyncio.run(engine._on_finding_created(_make_event("CWE-89", "high", "SQL Injection in login")))

    recs = engine.get_recommendations()
    assert len(recs) > 0, "SQLi finding should generate recommendations"

    rule_ids = [r["rule_id"] for r in recs]
    assert "generate_exploit" in rule_ids, "SQLi should suggest generating exploit"
    assert "fuzz_param" in rule_ids, "SQLi should suggest fuzzing"

    for r in recs:
        assert r["finding"]["cwe"] == "CWE-89"
        assert r["finding"]["severity"] == "high"
        assert r["dismissed"] == False
        assert r["executed"] == False
        assert r["priority"] > 0


def test_xss_finding_generates_recommendations():
    bus = EventBus()
    engine = RecommendationEngine(bus)

    import asyncio
    asyncio.run(engine._on_finding_created(_make_event("CWE-79", "medium", "Reflected XSS")))

    recs = engine.get_recommendations()
    rule_ids = [r["rule_id"] for r in recs]
    assert "fuzz_param" in rule_ids, "XSS should suggest fuzzing"
    assert "generate_exploit" in rule_ids, "XSS should suggest exploit"


def test_info_severity_skips_high_severity_rules():
    bus = EventBus()
    engine = RecommendationEngine(bus)

    import asyncio
    asyncio.run(engine._on_finding_created(_make_event("CWE-79", "info", "Low impact XSS")))

    recs = engine.get_recommendations()
    rule_ids = [r["rule_id"] for r in recs]
    assert "retest_finding" not in rule_ids, "Info severity should not suggest retest"
    assert "active_scan_endpoint" not in rule_ids, "Info severity should not suggest active scan"


def test_critical_finding_has_highest_priority():
    bus = EventBus()
    engine = RecommendationEngine(bus)

    import asyncio
    asyncio.run(engine._on_finding_created(_make_event("CWE-89", "critical", "Critical SQLi")))
    asyncio.run(engine._on_finding_created(_make_event("CWE-79", "low", "Low XSS")))

    recs = engine.get_recommendations()
    assert len(recs) >= 2
    critical_recs = [r for r in recs if r["finding"]["severity"] == "critical"]
    low_recs = [r for r in recs if r["finding"]["severity"] == "low"]
    if critical_recs and low_recs:
        assert critical_recs[0]["priority"] > low_recs[0]["priority"]


def test_dismiss_recommendation():
    bus = EventBus()
    engine = RecommendationEngine(bus)

    import asyncio
    asyncio.run(engine._on_finding_created(_make_event("CWE-89", "high")))

    recs = engine.get_recommendations()
    assert len(recs) > 0
    rec_id = recs[0]["id"]

    assert engine.dismiss_recommendation(rec_id) == True
    assert engine.dismiss_recommendation("nonexistent") == False
    assert len(engine.get_recommendations()) == len(recs) - 1


def test_mark_executed():
    bus = EventBus()
    engine = RecommendationEngine(bus)

    import asyncio
    asyncio.run(engine._on_finding_created(_make_event("CWE-89", "high")))

    recs = engine.get_recommendations()
    rec_id = recs[0]["id"]

    assert engine.mark_executed(rec_id) == True
    assert len(engine.get_recommendations()) == len(recs) - 1


def test_dismiss_all_for_finding():
    bus = EventBus()
    engine = RecommendationEngine(bus)

    import asyncio
    finding_id = str(uuid.uuid4())
    event = _make_event("CWE-89", "high")
    event["id"] = finding_id
    asyncio.run(engine._on_finding_created(event))

    count = engine.dismiss_all_for_finding(finding_id)
    assert count > 0, "Should dismiss at least one recommendation"
    assert engine.get_stats()["total"] == 0


def test_stats_by_rule_and_module():
    bus = EventBus()
    engine = RecommendationEngine(bus)

    import asyncio
    asyncio.run(engine._on_finding_created(_make_event("CWE-89", "high")))
    asyncio.run(engine._on_finding_created(_make_event("CWE-79", "high")))

    stats = engine.get_stats()
    assert stats["total"] > 0
    assert len(stats["by_rule"]) > 0
    assert len(stats["by_module"]) > 0


def test_duplicate_finding_does_not_duplicate():
    bus = EventBus()
    engine = RecommendationEngine(bus)

    import asyncio
    event = _make_event("CWE-89", "high")
    asyncio.run(engine._on_finding_created(event))
    asyncio.run(engine._on_finding_created(event))

    assert len(engine.get_recommendations()) == len(
        [r for r in engine._recommendations if not r["dismissed"] and not r["executed"]]
    )


def test_recommendation_has_required_fields():
    bus = EventBus()
    engine = RecommendationEngine(bus)

    import asyncio
    asyncio.run(engine._on_finding_created(_make_event("CWE-89", "high")))

    recs = engine.get_recommendations()
    for r in recs:
        assert "id" in r
        assert "rule_id" in r
        assert "label" in r
        assert "description" in r
        assert "module" in r
        assert "priority" in r
        assert "finding" in r
        assert "cwe" in r["finding"]
        assert "severity" in r["finding"]
        assert "title" in r["finding"]


def test_unsupported_cwe_generates_no_recommendations():
    bus = EventBus()
    engine = RecommendationEngine(bus)

    import asyncio
    asyncio.run(engine._on_finding_created(_make_event("CWE-999", "high", "Unknown vuln")))

    recs = engine.get_recommendations()
    for r in recs:
        assert r["rule_id"] not in ["fuzz_param", "generate_exploit"]

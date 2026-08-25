"""Tests for the new advanced scanner checks (deepseek v4-pro additions)."""
import pytest


class TestActiveSqliBlind:
    def test_module_imports(self):
        from modules.scanner.active.checks.active_sqli_blind import ActiveSqliBlindCheck
        check = ActiveSqliBlindCheck()
        assert check.name == "active_sqli_blind"

    def test_inject_payload_via_query(self):
        from modules.scanner.active.checks.active_sqli_blind import ActiveSqliBlindCheck
        from urllib.parse import unquote
        check = ActiveSqliBlindCheck()
        base = {"url": "http://example.com/page?id=1", "method": "GET"}
        modified = check._inject_payload(base, "id", "1' OR '1'='1")
        # urlencode uses + for spaces and encodes quotes; check key parts
        decoded = unquote(modified["url"])
        assert "1'" in decoded
        assert "1'='1" in decoded

    def test_inject_payload_param_not_present(self):
        # A param missing from the base URL must be ADDED, not skipped —
        # otherwise checks silently no-op on discovered params.
        from modules.scanner.active.checks.active_sqli_blind import ActiveSqliBlindCheck
        check = ActiveSqliBlindCheck()
        base = {"url": "http://example.com/page?id=1", "method": "GET"}
        modified = check._inject_payload(base, "nonexistent", "payload")
        assert "nonexistent=payload" in modified["url"]
        assert "id=1" in modified["url"]  # existing params preserved

    def test_blind_pairs_structure(self):
        from modules.scanner.active.checks.active_sqli_blind import BLIND_PAIRS
        assert len(BLIND_PAIRS) >= 5
        for t, f, op in BLIND_PAIRS:
            assert t != f, f"TRUE != FALSE for {op}"
            assert isinstance(op, str)


class TestActiveTimeBlind:
    def test_module_imports(self):
        from modules.scanner.active.checks.active_time_blind import ActiveTimeBlindCheck
        check = ActiveTimeBlindCheck()
        assert check.name == "active_time_blind"

    def test_payloads_structure(self):
        from modules.scanner.active.checks.active_time_blind import TIME_PAYLOADS
        assert len(TIME_PAYLOADS) >= 10
        categories = {cat for _, cat, _ in TIME_PAYLOADS}
        assert "sqli-mysql" in categories
        assert "cmdi" in categories
        assert "ssti-java" in categories

    @pytest.mark.asyncio
    async def test_baseline_measurement_unreachable(self):
        from modules.scanner.active.checks.active_time_blind import ActiveTimeBlindCheck
        import httpx
        check = ActiveTimeBlindCheck()
        async with httpx.AsyncClient(verify=False, timeout=1) as client:
            result = await check._measure_baseline(client, {"url": "http://192.0.2.1:9999", "method": "GET"})
            assert result is None  # unreachable host


class TestPassiveInfoDisclosure:
    def test_module_imports(self):
        from modules.scanner.passive.checks.passive_info_disclosure import PassiveInfoDisclosureCheck
        check = PassiveInfoDisclosureCheck()
        assert check.name == "passive_info_disclosure"

    def test_luhn_valid_card(self):
        from modules.scanner.passive.checks.passive_info_disclosure import PassiveInfoDisclosureCheck
        check = PassiveInfoDisclosureCheck()
        assert check._luhn_check("4111111111111111") is True
        assert check._luhn_check("5500000000000004") is True

    def test_luhn_invalid_card(self):
        from modules.scanner.passive.checks.passive_info_disclosure import PassiveInfoDisclosureCheck
        check = PassiveInfoDisclosureCheck()
        assert check._luhn_check("1234567890123456") is False
        assert check._luhn_check("") is False

    def test_luhn_amex(self):
        from modules.scanner.passive.checks.passive_info_disclosure import PassiveInfoDisclosureCheck
        check = PassiveInfoDisclosureCheck()
        assert check._luhn_check("378282246310005") is True  # Amex test number

    @pytest.mark.asyncio
    async def test_no_body_returns_empty(self):
        from modules.scanner.passive.checks.passive_info_disclosure import PassiveInfoDisclosureCheck
        check = PassiveInfoDisclosureCheck()
        results = await check.run({"body": ""}, {})
        assert results == []

    @pytest.mark.asyncio
    async def test_detect_credit_card(self):
        from modules.scanner.passive.checks.passive_info_disclosure import PassiveInfoDisclosureCheck
        check = PassiveInfoDisclosureCheck()
        results = await check.run({"body": "Payment with card 4111-1111-1111-1111 processed."}, {})
        assert len(results) >= 1
        assert "Credit Card" in results[0].title

    @pytest.mark.asyncio
    async def test_detect_aws_key(self):
        from modules.scanner.passive.checks.passive_info_disclosure import PassiveInfoDisclosureCheck
        check = PassiveInfoDisclosureCheck()
        results = await check.run({"body": '{"access_key": "AKIAIOSFODNN7EXAMPLE"}'}, {})
        assert len(results) >= 1
        assert "AWS" in results[0].title

    @pytest.mark.asyncio
    async def test_detect_stack_trace(self):
        from modules.scanner.passive.checks.passive_info_disclosure import PassiveInfoDisclosureCheck
        check = PassiveInfoDisclosureCheck()
        trace = "Traceback (most recent call last):\n  File 'app.py', line 42, in handler\n    return 1/0"
        results = await check.run({"body": trace}, {})
        assert len(results) >= 1
        assert "Traceback" in results[0].title

    @pytest.mark.asyncio
    async def test_detect_internal_ip(self):
        from modules.scanner.passive.checks.passive_info_disclosure import PassiveInfoDisclosureCheck
        check = PassiveInfoDisclosureCheck()
        results = await check.run({"body": "Connected to database at 192.168.1.100"}, {})
        assert len(results) >= 1
        assert "IP" in results[0].title


class TestPassiveTechFingerprint:
    def test_module_imports(self):
        from modules.scanner.passive.checks.passive_tech_fingerprint import PassiveTechFingerprintCheck
        check = PassiveTechFingerprintCheck()
        assert check.name == "passive_tech_fingerprint"

    @pytest.mark.asyncio
    async def test_detect_wordpress(self):
        from modules.scanner.passive.checks.passive_tech_fingerprint import PassiveTechFingerprintCheck
        check = PassiveTechFingerprintCheck()
        body = '<meta name="generator" content="WordPress 6.5"/>' * 5
        results = await check.run({"body": body, "headers": {}}, {})
        assert len(results) >= 1
        assert "WordPress" in results[0].title

    @pytest.mark.asyncio
    async def test_detect_react(self):
        from modules.scanner.passive.checks.passive_tech_fingerprint import PassiveTechFingerprintCheck
        check = PassiveTechFingerprintCheck()
        results = await check.run({"body": '<script src="/react@18.2.0.js"></script>', "headers": {}}, {})
        assert len(results) >= 1
        assert "React" in results[0].title

    @pytest.mark.asyncio
    async def test_detect_nginx_header(self):
        from modules.scanner.passive.checks.passive_tech_fingerprint import PassiveTechFingerprintCheck
        check = PassiveTechFingerprintCheck()
        # Need at least minimal body for the check to proceed
        results = await check.run({"body": "<html></html>", "headers": {"Server": "nginx/1.25.4"}}, {})
        assert len(results) >= 1
        assert "Nginx" in results[0].title

    @pytest.mark.asyncio
    async def test_empty_body_no_results(self):
        from modules.scanner.passive.checks.passive_tech_fingerprint import PassiveTechFingerprintCheck
        check = PassiveTechFingerprintCheck()
        results = await check.run({"body": "", "headers": {}}, {})
        assert results == []
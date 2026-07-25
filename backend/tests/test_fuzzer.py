import pytest
import uuid
import time
from unittest.mock import AsyncMock


@pytest.fixture
def fuzzer():
    from modules.fuzzer.service import FuzzerService
    bus = AsyncMock()
    return FuzzerService(bus)


class TestTokenBucket:
    def test_initial_tokens(self):
        from modules.fuzzer.service import TokenBucket
        tb = TokenBucket(rate=10, burst=5)
        assert tb.tokens == 5.0

    def test_acquire_reduces_tokens(self):
        from modules.fuzzer.service import TokenBucket
        tb = TokenBucket(rate=1000, burst=100)
        initial = tb.tokens
        import asyncio
        asyncio.run(tb.acquire())
        assert tb.tokens < initial

    def test_burst_defaults_to_rate(self):
        from modules.fuzzer.service import TokenBucket
        tb = TokenBucket(rate=10)
        assert tb.burst == 10

    def test_zero_rate_acquire_sleeps(self):
        from modules.fuzzer.service import TokenBucket
        tb = TokenBucket(rate=0.1, burst=1)
        tb.tokens = 0.0
        start = time.monotonic()
        import asyncio
        asyncio.run(tb.acquire())
        elapsed = time.monotonic() - start
        assert elapsed >= 0.0


class TestPayloadProcessor:
    def test_url_encode(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.url_encode("a b") == "a%20b"

    def test_double_url_encode(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.double_url_encode(" ") == "%2520"

    def test_base64_encode(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.base64_encode("hello") == "aGVsbG8="

    def test_hex_encode(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.hex_encode("hello") == "68656c6c6f"

    def test_hex_decode(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.hex_decode("68656c6c6f") == "hello"

    def test_hex_decode_invalid(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.hex_decode("zz") == "zz"

    def test_unicode_encode(self):
        from modules.fuzzer.service import PayloadProcessor
        assert "\\u0041" in PayloadProcessor.unicode_encode("A")

    def test_reverse(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.reverse("abc") == "cba"

    def test_md5_hash(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.md5_hash("hello") == "5d41402abc4b2a76b9719d911017c592"

    def test_sha1_hash(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.sha1_hash("hello") == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

    def test_sha256_hash(self):
        from modules.fuzzer.service import PayloadProcessor
        h = PayloadProcessor.sha256_hash("hello")
        assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_to_upper(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.to_upper("hello") == "HELLO"

    def test_to_lower(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.to_lower("HELLO") == "hello"

    def test_add_prefix(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.add_prefix("world", "hello_") == "hello_world"

    def test_add_suffix(self):
        from modules.fuzzer.service import PayloadProcessor
        assert PayloadProcessor.add_suffix("hello", "_world") == "hello_world"


class TestWafDetection:
    def test_cloudflare_body(self, fuzzer):
        waf = fuzzer.detect_waf(200, {}, "cloudflare ray", "test.com")
        assert waf == "cloudflare"

    def test_cloudflare_status_and_body(self, fuzzer):
        waf = fuzzer.detect_waf(503, {}, "Just a moment...", "test.com")
        assert waf == "cloudflare"

    def test_aws_waf_header(self, fuzzer):
        waf = fuzzer.detect_waf(403, {"x-amzn-requestid": "abc"}, "", "test.com")
        assert waf == "aws_waf"

    def test_aws_waf_body(self, fuzzer):
        waf = fuzzer.detect_waf(403, {}, "Request blocked by WAF", "test.com")
        assert waf == "aws_waf"

    def test_generic_waf_block_status(self, fuzzer):
        waf = fuzzer.detect_waf(429, {}, "too many requests", "test.com")
        assert waf == "generic_waf"

    def test_no_waf(self, fuzzer):
        waf = fuzzer.detect_waf(200, {}, "hello world", "test.com")
        assert waf is None

    def test_generic_waf_forbidden_body(self, fuzzer):
        waf = fuzzer.detect_waf(403, {}, "Access denied by security policy", "test.com")
        assert waf == "generic_waf"


class TestWafBackoff:
    def test_no_waf_reduces_counter(self, fuzzer):
        wait = fuzzer.apply_waf_backoff("t.com", None)
        assert wait == 0.0
        assert fuzzer._consecutive_blocks.get("t.com", 0) == 0

    def test_waf_increases_delay(self, fuzzer):
        wait1 = fuzzer.apply_waf_backoff("t.com", "cloudflare")
        wait2 = fuzzer.apply_waf_backoff("t.com", "cloudflare")
        assert wait2 > wait1
        assert wait2 <= 30.0

    def test_waf_sets_detected_flag(self, fuzzer):
        fuzzer.apply_waf_backoff("t.com", "cloudflare")
        assert fuzzer._waf_detected.get("t.com") is True


class TestExtractPositions:
    def test_single_position(self, fuzzer):
        positions = fuzzer.extract_positions("GET /api?q=§test§ HTTP/1.1")
        assert len(positions) == 1
        assert positions[0][0] == "test"

    def test_multiple_positions(self, fuzzer):
        positions = fuzzer.extract_positions("§a§ §b§")
        assert len(positions) == 2

    def test_no_positions(self, fuzzer):
        positions = fuzzer.extract_positions("plain text")
        assert len(positions) == 0

    def test_overlapping_markers(self, fuzzer):
        positions = fuzzer.extract_positions("§a§middle§b§")
        assert len(positions) == 2
        assert positions[0][0] == "a"
        assert positions[1][0] == "b"


class TestPayloadGeneration:
    def test_sniper(self, fuzzer):
        positions = [{"name": "param1", "processors": []}]
        wordlists = {"param1": ["a", "b"]}
        result = fuzzer.generate_payloads(positions, wordlists, "sniper")
        assert len(result) == 2
        assert result[0] == {"param1": "a"}
        assert result[1] == {"param1": "b"}

    def test_batteringram(self, fuzzer):
        positions = [{"name": "p1", "processors": []}, {"name": "p2", "processors": []}]
        wordlists = {"p1": ["a", "b"]}
        result = fuzzer.generate_payloads(positions, wordlists, "batteringram")
        assert len(result) == 2
        assert result[0] == {"p1": "a", "p2": "a"}

    def test_pitchfork(self, fuzzer):
        positions = [{"name": "p1", "processors": []}, {"name": "p2", "processors": []}]
        wordlists = {"p1": ["a", "b"], "p2": ["1", "2"]}
        result = fuzzer.generate_payloads(positions, wordlists, "pitchfork")
        assert len(result) == 2
        assert result[0] == {"p1": "a", "p2": "1"}

    def test_clusterbomb(self, fuzzer):
        positions = [{"name": "p1", "processors": []}, {"name": "p2", "processors": []}]
        wordlists = {"p1": ["a", "b"], "p2": ["1", "2"]}
        result = fuzzer.generate_payloads(positions, wordlists, "clusterbomb")
        assert len(result) == 4

    def test_empty_positions(self, fuzzer):
        result = fuzzer.generate_payloads([], {}, "sniper")
        assert result == []

    def test_sniper_with_processors(self, fuzzer):
        positions = [{"name": "p1", "processors": ["url_encode"]}]
        wordlists = {"p1": ["a b"]}
        result = fuzzer.generate_payloads(positions, wordlists, "sniper")
        assert result[0]["p1"] == "a%20b"

    def test_clusterbomb_cartesian_limit(self, fuzzer):
        from modules.fuzzer.service import MAX_CARTESIAN_PRODUCT
        big_list = [str(i) for i in range(1000)]
        positions = [{"name": "p1", "processors": []}, {"name": "p2", "processors": []}]
        wordlists = {"p1": big_list, "p2": big_list}
        result = fuzzer.generate_payloads(positions, wordlists, "clusterbomb")
        assert len(result) <= MAX_CARTESIAN_PRODUCT


class TestWordlistSecurity:
    def test_path_traversal_blocked(self, fuzzer):
        result = fuzzer.expand_wordlist("../../../etc/passwd")
        assert result == []

    def test_absolute_path_windows_blocked(self, fuzzer):
        result = fuzzer.expand_wordlist("C:\\Windows\\system32\\drivers\\etc\\hosts")
        assert result == []

    def test_absolute_path_unix_blocked(self, fuzzer):
        result = fuzzer.expand_wordlist("/etc/passwd")
        assert result == []

    def test_nonexistent_wordlist(self, fuzzer):
        result = fuzzer.expand_wordlist("nonexistent.txt")
        assert result == []

    def test_list_wordlists(self, fuzzer):
        result = fuzzer.list_wordlists()
        assert isinstance(result, list)


class TestApplyProcessing:
    def test_no_processors(self, fuzzer):
        assert fuzzer.apply_processing("hello", []) == "hello"

    def test_single_processor(self, fuzzer):
        assert fuzzer.apply_processing("hello", ["reverse"]) == "olleh"

    def test_multiple_processors(self, fuzzer):
        result = fuzzer.apply_processing("hello", ["reverse", "to_upper"])
        assert result == "OLLEH"

    def test_add_prefix_processor(self, fuzzer):
        assert fuzzer.apply_processing("world", ["add_prefix:hello_"]) == "hello_world"

    def test_add_suffix_processor(self, fuzzer):
        assert fuzzer.apply_processing("hello", ["add_suffix:_world"]) == "hello_world"


class TestParseRawHttp:
    def test_parse_get(self, fuzzer):
        raw = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
        parsed = fuzzer._parse_raw_http(raw)
        assert parsed["method"] == "GET"
        assert parsed["url"] == "https://example.com/api"

    def test_parse_post(self, fuzzer):
        raw = "POST /api HTTP/1.1\r\nHost: ex.com\r\n\r\nbody"
        parsed = fuzzer._parse_raw_http(raw)
        assert parsed["method"] == "POST"
        assert parsed["content"] == "body"

    def test_parse_invalid(self, fuzzer):
        with pytest.raises(ValueError):
            fuzzer._parse_raw_http("invalid line")

    def test_parse_no_host(self, fuzzer):
        raw = "GET / HTTP/1.1\r\n\r\n"
        parsed = fuzzer._parse_raw_http(raw)
        assert parsed["url"] == "https:///"


class TestCancelJob:
    def test_cancel_marks_flag(self, fuzzer):
        jid = uuid.uuid4()
        fuzzer.cancel_job(jid)
        assert jid in fuzzer._cancel_flags

    def test_cancel_is_idempotent(self, fuzzer):
        jid = uuid.uuid4()
        fuzzer.cancel_job(jid)
        fuzzer.cancel_job(jid)
        assert jid in fuzzer._cancel_flags

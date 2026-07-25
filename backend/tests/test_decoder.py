import pytest
from modules.decoder.service import DecoderService


@pytest.fixture
def svc():
    return DecoderService()


class TestBase64:
    def test_base64_encode(self, svc):
        assert svc.decode("hello", "base64_encode") == "aGVsbG8="

    def test_base64_decode(self, svc):
        assert svc.decode("aGVsbG8=", "base64_decode") == "hello"

    def test_base64url_encode(self, svc):
        result = svc.decode("hello?", "base64url_encode")
        assert result == "aGVsbG8_"

    def test_base64url_decode(self, svc):
        result = svc.decode("aGVsbG8_", "base64url_decode")
        assert result == "hello?"

    def test_base64_decode_padding_required(self, svc):
        with pytest.raises(Exception):
            svc.decode("aGVsbG8", "base64_decode")


class TestUrlCodec:
    def test_url_encode(self, svc):
        assert svc.decode("a b", "url_encode") == "a%20b"
        assert svc.decode("a/b", "url_encode") == "a%2Fb"

    def test_url_decode(self, svc):
        assert svc.decode("a%20b", "url_decode") == "a b"
        assert svc.decode("a%2Fb", "url_decode") == "a/b"


class TestHexCodec:
    def test_hex_encode(self, svc):
        assert svc.decode("hello", "hex_encode") == "68656c6c6f"

    def test_hex_decode(self, svc):
        assert svc.decode("68656c6c6f", "hex_decode") == "hello"


class TestHtmlCodec:
    def test_html_encode(self, svc):
        assert svc.decode("<script>", "html_encode") == "&lt;script&gt;"

    def test_html_decode(self, svc):
        assert svc.decode("&lt;script&gt;", "html_decode") == "<script>"


class TestHashing:
    def test_md5(self, svc):
        assert svc.decode("hello", "md5") == "5d41402abc4b2a76b9719d911017c592"

    def test_sha1(self, svc):
        assert svc.decode("hello", "sha1") == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

    def test_sha224(self, svc):
        h = svc.decode("hello", "sha224")
        assert len(h) == 56

    def test_sha256(self, svc):
        h = svc.decode("hello", "sha256")
        assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_sha384(self, svc):
        h = svc.decode("hello", "sha384")
        assert len(h) == 96

    def test_sha512(self, svc):
        h = svc.decode("hello", "sha512")
        assert len(h) == 128


class TestJwtDecode:
    def test_jwt_decode_valid(self, svc, sample_jwt):
        result = svc.decode(sample_jwt, "jwt_decode")
        assert "header" in result
        assert "payload" in result
        assert '"alg": "HS256"' in result
        assert '"sub": "123"' in result

    def test_jwt_decode_invalid_format(self, svc):
        with pytest.raises(ValueError, match="expected 3 parts"):
            svc.decode("invalid", "jwt_decode")


class TestUnicode:
    def test_unicode_escape(self, svc):
        result = svc.decode("\n", "unicode_escape")
        assert "\\n" in result

    def test_unicode_unescape(self, svc):
        assert svc.decode("\\u0048\\u0069", "unicode_unescape") == "Hi"


class TestUnknownCodec:
    def test_unknown_codec(self, svc):
        with pytest.raises(ValueError, match="Unknown codec"):
            svc.decode("test", "nonexistent")


class TestSmartDecode:
    def test_smart_decode_base64(self, svc):
        results = svc.smart_decode("aGVsbG8=")
        assert any(r["codec"] == "base64_decode" for r in results)
        decoded = [r for r in results if r["codec"] == "base64_decode"]
        assert decoded[0]["output"] == "hello"

    def test_smart_decode_hex(self, svc):
        results = svc.smart_decode("68656c6c6f")
        assert any(r["codec"] == "hex_decode" for r in results)
        decoded = [r for r in results if r["codec"] == "hex_decode"]
        assert decoded[0]["output"] == "hello"

    def test_smart_decode_url(self, svc):
        results = svc.smart_decode("hello%20world")
        assert any(r["codec"] == "url_decode" for r in results)
        decoded = [r for r in results if r["codec"] == "url_decode"]
        assert decoded[0]["output"] == "hello world"

    def test_smart_decode_html(self, svc):
        results = svc.smart_decode("&lt;hello&gt;")
        assert any(r["codec"] == "html_decode" for r in results)
        decoded = [r for r in results if r["codec"] == "html_decode"]
        assert decoded[0]["output"] == "<hello>"

    def test_smart_decode_unicode(self, svc):
        results = svc.smart_decode("\\u0048\\u0069")
        assert any(r["codec"] == "unicode_unescape" for r in results)
        decoded = [r for r in results if r["codec"] == "unicode_unescape"]
        assert decoded[0]["output"] == "Hi"

    def test_smart_decode_plain_text(self, svc):
        results = svc.smart_decode("hello world")
        assert len(results) == 0

    def test_smart_decode_empty(self, svc):
        results = svc.smart_decode("")
        assert len(results) == 0

    def test_smart_decode_confidence_ordering(self, svc):
        results = svc.smart_decode("aGVsbG8=")
        if len(results) >= 2:
            assert results[0]["confidence"] >= results[1]["confidence"]


class TestHashIdentifier:
    def test_md5_identified(self, svc):
        results = svc.hash_identifier("5d41402abc4b2a76b9719d911017c592")
        assert any(r["hash_type"] == "MD5" for r in results)
        md5 = [r for r in results if r["hash_type"] == "MD5"][0]
        assert md5["length"] == 32
        assert md5["bit_length"] == 128

    def test_sha1_identified(self, svc):
        results = svc.hash_identifier("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        assert any(r["hash_type"] == "SHA-1" for r in results)

    def test_sha256_identified(self, svc):
        results = svc.hash_identifier("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert any(r["hash_type"] == "SHA-256" for r in results)

    def test_sha512_identified(self, svc):
        results = svc.hash_identifier(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
        assert any(r["hash_type"] == "SHA-512" for r in results)

    def test_unknown_hash_length(self, svc):
        results = svc.hash_identifier("abcdef")
        assert results[0]["hash_type"] == "Unknown"

    def test_hmincluded(self, svc):
        results = svc.hash_identifier("5d41402abc4b2a76b9719d911017c592")
        assert any(r["hash_type"] == "HMAC-MD5" for r in results)


class TestHexDump:
    def test_hex_dump_basic(self, svc):
        result = svc.hex_dump("hello")
        assert "68 65 6c 6c" in result
        assert "hello" in result
        assert result.startswith("00000000")

    def test_hex_dump_longer(self, svc):
        data = "A" * 32
        result = svc.hex_dump(data)
        lines = result.split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("00000000")
        assert lines[1].startswith("00000010")

import base64
import urllib.parse
import hashlib
import json
import html as html_mod
import re
import math
import struct
import zlib
import gzip as gzip_mod
import quopri
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ---- Simple base91 implementation ----
_b91_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
_b91_decode_map = {c: i for i, c in enumerate(_b91_alphabet)}


def _b91encode(data: bytes) -> str:
    b = 0
    n = 0
    out = []
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(_b91_alphabet[v % 91])
            out.append(_b91_alphabet[v // 91])
    if n:
        out.append(_b91_alphabet[b % 91])
        if n > 7 or b > 90:
            out.append(_b91_alphabet[b // 91])
    return "".join(out)


def _b91decode(s: str) -> bytes:
    v = -1
    b = 0
    n = 0
    out = bytearray()
    for c in s:
        try:
            p = _b91_decode_map[c]
        except KeyError:
            continue
        if v < 0:
            v = p
        else:
            v += p * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1
    if v >= 0:
        b |= v << n
        out.append(b & 255)
    return bytes(out)


class DecoderService:
    def decode(self, input_str: str, codec: str) -> str:
        match codec:
            case "base64_encode":
                return base64.b64encode(input_str.encode()).decode()
            case "base64_decode":
                return base64.b64decode(input_str.encode()).decode("utf-8", errors="replace")
            case "base64url_encode":
                return base64.urlsafe_b64encode(input_str.encode()).decode()
            case "base64url_decode":
                return base64.urlsafe_b64decode(input_str.encode()).decode("utf-8", errors="replace")
            case "base32_encode":
                return base64.b32encode(input_str.encode()).decode()
            case "base32_decode":
                return base64.b32decode(input_str.encode()).decode("utf-8", errors="replace")
            case "base85_encode":
                return base64.a85encode(input_str.encode()).decode()
            case "base85_decode":
                return base64.a85decode(input_str.encode()).decode("utf-8", errors="replace")
            case "base91_encode":
                return _b91encode(input_str.encode())
            case "base91_decode":
                return _b91decode(input_str).decode("utf-8", errors="replace")
            case "url_encode":
                return urllib.parse.quote(input_str, safe="")
            case "url_decode":
                return urllib.parse.unquote(input_str)
            case "url_encode_all":
                return "".join(f"%{ord(c):02X}" for c in input_str)
            case "url_encode_double":
                return "".join(f"%25{ord(c):02X}" for c in input_str)
            case "url_decode_all":
                s = input_str
                while True:
                    prev = s
                    s = re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)
                    if s == prev:
                        break
                return s
            case "smart_url_decode":
                s = input_str
                depth = 0
                while re.search(r"%[0-9a-fA-F]{2}", s) and depth < 10:
                    prev = s
                    s = urllib.parse.unquote(s)
                    if s == prev:
                        break
                    depth += 1
                return s
            case "hex_encode":
                return input_str.encode().hex()
            case "hex_decode":
                return bytes.fromhex(input_str).decode("utf-8", errors="replace")
            case "binary_encode":
                return " ".join(format(b, "08b") for b in input_str.encode())
            case "binary_decode":
                return bytes(int(b, 2) for b in input_str.split()).decode("utf-8", errors="replace")
            case "octal_encode":
                return "".join(f"\\{ord(c):03o}" for c in input_str)
            case "octal_decode":
                return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), input_str)
            case "html_encode":
                return html_mod.escape(input_str)
            case "html_decode":
                return html_mod.unescape(input_str)
            case "unicode_escape":
                return input_str.encode("unicode_escape").decode()
            case "unicode_unescape":
                return input_str.encode().decode("unicode_escape")
            case "punycode_encode":
                return input_str.encode("idna").decode()
            case "punycode_decode":
                return input_str.encode().decode("idna")
            case "quoted_printable_encode":
                return quopri.encodestring(input_str.encode()).decode()
            case "quoted_printable_decode":
                return quopri.decodestring(input_str.encode()).decode("utf-8", errors="replace")
            case "rot13":
                return input_str.translate(str.maketrans(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
                ))
            case "zlib_compress":
                return base64.b64encode(zlib.compress(input_str.encode())).decode()
            case "zlib_decompress":
                return zlib.decompress(base64.b64decode(input_str)).decode("utf-8", errors="replace")
            case "gzip":
                return base64.b64encode(gzip_mod.compress(input_str.encode())).decode()
            case "gunzip":
                return gzip_mod.decompress(base64.b64decode(input_str)).decode("utf-8", errors="replace")
            case "md5":
                return hashlib.md5(input_str.encode()).hexdigest()
            case "sha1":
                return hashlib.sha1(input_str.encode()).hexdigest()
            case "sha224":
                return hashlib.sha224(input_str.encode()).hexdigest()
            case "sha256":
                return hashlib.sha256(input_str.encode()).hexdigest()
            case "sha384":
                return hashlib.sha384(input_str.encode()).hexdigest()
            case "sha512":
                return hashlib.sha512(input_str.encode()).hexdigest()
            case "jwt_decode":
                return self._decode_jwt(input_str)
            case _:
                raise ValueError(f"Unknown codec: {codec}")

    def _decode_jwt(self, token: str) -> str:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT: expected 3 parts separated by dots")
        def _b64decode(part: str) -> dict:
            padded = part + "=" * (4 - len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
        return json.dumps({
            "header": _b64decode(parts[0]),
            "payload": _b64decode(parts[1]),
            "signature_raw": parts[2],
        }, indent=2)

    def smart_decode(self, input_str: str) -> list[dict]:
        results = []
        seen_outputs = set()

        def add_result(codec: str, output: str, confidence: float):
            if output not in seen_outputs and output != input_str:
                seen_outputs.add(output)
                results.append({
                    "codec": codec,
                    "output": output,
                    "confidence": round(min(confidence, 1.0), 2)
                })

        s = input_str.strip()

        if self._looks_like_base64(s):
            try:
                decoded = base64.b64decode(s)
                text = decoded.decode("utf-8", errors="replace")
                printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
                ratio = printable / len(decoded) if decoded else 0
                valid_utf8 = 0.3
                try:
                    decoded.decode("utf-8")
                    valid_utf8 = 1.0
                except UnicodeDecodeError:
                    pass
                conf = ratio * 0.4 + valid_utf8 * 0.4 + 0.1
                if ratio < 0.4:
                    conf *= 0.3
                add_result("base64_decode", text, conf)
            except Exception:
                pass

        if self._looks_like_hex(s):
            try:
                decoded = bytes.fromhex(s)
                text = decoded.decode("utf-8", errors="replace")
                printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
                ratio = printable / len(decoded) if decoded else 0
                valid_utf8 = 0.3
                try:
                    decoded.decode("utf-8")
                    valid_utf8 = 1.0
                except UnicodeDecodeError:
                    pass
                conf = ratio * 0.4 + valid_utf8 * 0.4 + 0.1
                if ratio < 0.3:
                    conf *= 0.2
                add_result("hex_decode", text, conf)
            except Exception:
                pass

        if "%" in s and re.search(r"%[0-9a-fA-F]{2}", s):
            try:
                decoded = urllib.parse.unquote(s)
                if decoded != s:
                    pct_count = len(re.findall(r"%[0-9a-fA-F]{2}", s))
                    conf = min(0.5 + pct_count * 0.05, 0.95)
                    add_result("url_decode", decoded, conf)
            except Exception:
                pass

        if "&" in s and ";" in s:
            try:
                decoded = html_mod.unescape(s)
                if decoded != s:
                    conf = 0.6
                    add_result("html_decode", decoded, conf)
            except Exception:
                pass

        if "\\u" in s and re.search(r"\\u[0-9a-fA-F]{4}", s):
            try:
                decoded = s.encode("utf-8").decode("unicode_escape")
                if decoded != s:
                    conf = 0.7
                    add_result("unicode_unescape", decoded, conf)
            except Exception:
                pass

        if re.search(r"\\[0-7]{3}", s):
            try:
                decoded = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), s)
                if decoded != s:
                    add_result("octal_decode", decoded, 0.5)
            except Exception:
                pass

        if re.search(r"&#x[0-9a-fA-F]+;|&#\d+;", s):
            try:
                decoded = html_mod.unescape(s)
                if decoded != s:
                    add_result("html_decode", decoded, 0.65)
            except Exception:
                pass

        results.sort(key=lambda x: x["confidence"], reverse=True)
        return results

    def recursive_smart_decode(self, input_str: str) -> list[dict]:
        chain = []
        current = input_str.strip()
        max_depth = 10
        all_codecs = [
            ("base64_decode", self._looks_like_base64, self._try_base64),
            ("hex_decode", self._looks_like_hex, self._try_hex),
            ("url_decode", lambda s: "%" in s and re.search(r"%[0-9a-fA-F]{2}", s), self._try_url),
            ("html_decode", lambda s: "&" in s and ";" in s, self._try_html),
            ("unicode_unescape", lambda s: "\\u" in s and re.search(r"\\u[0-9a-fA-F]{4}", s), self._try_unicode),
            ("octal_decode", lambda s: re.search(r"\\[0-7]{3}", s), self._try_octal),
            ("base32_decode", self._looks_like_base32, self._try_base32),
            ("base85_decode", self._looks_like_base85, self._try_base85),
            ("base91_decode", self._looks_like_base91, self._try_base91),
            ("quoted_printable_decode", lambda s: "=" in s and re.search(r"=[0-9a-fA-F]{2}", s), self._try_qp),
            ("rot13", lambda s: bool(re.search(r"[A-Za-z]", s)), self._try_rot13),
        ]

        for depth in range(max_depth):
            best = None
            best_result = None
            best_conf = 0.0

            for codec_name, checker, try_fn in all_codecs:
                if not checker(current):
                    continue
                try:
                    result_text, conf = try_fn(current)
                    if result_text and result_text != current and conf > best_conf:
                        best = codec_name
                        best_result = result_text
                        best_conf = conf
                except Exception:
                    continue

            if best is None:
                break

            chain.append({
                "step": depth + 1,
                "codec": best,
                "intermediate": best_result,
                "confidence": round(min(best_conf, 1.0), 2),
            })
            current = best_result

        if not chain:
            chain.append({
                "step": 1,
                "codec": "none",
                "intermediate": current,
                "confidence": 0.0,
                "message": "No encoding detected"
            })

        chain.append({
            "step": len(chain) + 1,
            "codec": "final",
            "intermediate": current,
            "confidence": 1.0,
        })

        return chain

    def _try_base64(self, s: str) -> tuple[Optional[str], float]:
        decoded = base64.b64decode(s)
        text = decoded.decode("utf-8", errors="replace")
        printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
        ratio = printable / len(decoded) if decoded else 0
        valid_utf8 = 1.0 if self._is_valid_utf8(decoded) else 0.3
        conf = ratio * 0.4 + valid_utf8 * 0.4 + 0.1
        if ratio < 0.4:
            conf *= 0.3
        return text, conf

    def _try_hex(self, s: str) -> tuple[Optional[str], float]:
        decoded = bytes.fromhex(s)
        text = decoded.decode("utf-8", errors="replace")
        printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
        ratio = printable / len(decoded) if decoded else 0
        valid_utf8 = 1.0 if self._is_valid_utf8(decoded) else 0.3
        conf = ratio * 0.4 + valid_utf8 * 0.4 + 0.1
        if ratio < 0.3:
            conf *= 0.2
        return text, conf

    def _try_url(self, s: str) -> tuple[Optional[str], float]:
        decoded = urllib.parse.unquote(s)
        if decoded != s:
            pct_count = len(re.findall(r"%[0-9a-fA-F]{2}", s))
            conf = min(0.5 + pct_count * 0.05, 0.95)
            return decoded, conf
        return None, 0.0

    def _try_html(self, s: str) -> tuple[Optional[str], float]:
        decoded = html_mod.unescape(s)
        if decoded != s:
            return decoded, 0.6
        return None, 0.0

    def _try_unicode(self, s: str) -> tuple[Optional[str], float]:
        decoded = s.encode("utf-8").decode("unicode_escape")
        if decoded != s:
            return decoded, 0.7
        return None, 0.0

    def _try_octal(self, s: str) -> tuple[Optional[str], float]:
        decoded = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), s)
        if decoded != s:
            return decoded, 0.5
        return None, 0.0

    def _try_base32(self, s: str) -> tuple[Optional[str], float]:
        decoded = base64.b32decode(s)
        text = decoded.decode("utf-8", errors="replace")
        printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
        ratio = printable / len(decoded) if decoded else 0
        conf = 0.3 + ratio * 0.4
        if self._is_valid_utf8(decoded):
            conf += 0.3
        return text, conf

    def _try_base85(self, s: str) -> tuple[Optional[str], float]:
        decoded = base64.a85decode(s)
        text = decoded.decode("utf-8", errors="replace")
        printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
        ratio = printable / len(decoded) if decoded else 0
        conf = 0.3 + ratio * 0.4
        if self._is_valid_utf8(decoded):
            conf += 0.3
        return text, conf

    def _try_base91(self, s: str) -> tuple[Optional[str], float]:
        decoded = _b91decode(s)
        text = decoded.decode("utf-8", errors="replace")
        printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
        ratio = printable / len(decoded) if decoded else 0
        conf = 0.3 + ratio * 0.4
        if self._is_valid_utf8(decoded):
            conf += 0.3
        return text, conf

    def _try_qp(self, s: str) -> tuple[Optional[str], float]:
        decoded = quopri.decodestring(s.encode()).decode("utf-8", errors="replace")
        if decoded != s:
            eq_count = len(re.findall(r"=[0-9a-fA-F]{2}", s))
            conf = min(0.3 + eq_count * 0.05, 0.9)
            return decoded, conf
        return None, 0.0

    def _try_rot13(self, s: str) -> tuple[Optional[str], float]:
        decoded = s.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))
        if decoded != s:
            return decoded, 0.4
        return None, 0.0

    def _is_valid_utf8(self, data: bytes) -> bool:
        try:
            data.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False
        except Exception:
            return False

    def _looks_like_base64(self, s: str) -> bool:
        if not s:
            return False
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        return all(c in allowed for c in s) and len(s) % 4 == 0 and len(s) >= 4

    def _looks_like_hex(self, s: str) -> bool:
        if not s:
            return False
        return all(c in "0123456789abcdefABCDEF" for c in s) and len(s) >= 2 and len(s) % 2 == 0

    def _looks_like_base32(self, s: str) -> bool:
        if not s:
            return False
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
        return all(c in allowed for c in s) and len(s) >= 4

    def _looks_like_base85(self, s: str) -> bool:
        if not s:
            return False
        return s.startswith("<~") and s.endswith("~>") and len(s) >= 6

    def _looks_like_base91(self, s: str) -> bool:
        if not s or len(s) < 4:
            return False
        allowed = set(_b91_alphabet)
        return all(c in allowed for c in s)

    def convert_encoding(self, input_str: str, from_encoding: str, to_encoding: str) -> str:
        intermediate = self._decode_raw(input_str, from_encoding)
        return self._encode_raw(intermediate, to_encoding)

    def _decode_raw(self, data: str, encoding: str) -> bytes:
        match encoding:
            case "hex":
                return bytes.fromhex(data)
            case "base64":
                return base64.b64decode(data)
            case "base32":
                return base64.b32decode(data)
            case "base85":
                return base64.a85decode(data)
            case "binary":
                return bytes(int(b, 2) for b in data.split())
            case "octal":
                return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), data).encode()
            case "decimal":
                return bytes(int(x) for x in data.split())
            case "ascii":
                return data.encode("ascii", errors="replace")
            case "utf8":
                return data.encode("utf-8")
            case _:
                raise ValueError(f"Unknown encoding: {encoding}")

    def _encode_raw(self, data: bytes, encoding: str) -> str:
        match encoding:
            case "hex":
                return data.hex()
            case "base64":
                return base64.b64encode(data).decode()
            case "base32":
                return base64.b32encode(data).decode()
            case "base85":
                return base64.a85encode(data).decode()
            case "binary":
                return " ".join(format(b, "08b") for b in data)
            case "octal":
                return "".join(f"\\{b:03o}" for b in data)
            case "decimal":
                return " ".join(str(b) for b in data)
            case "ascii":
                return data.decode("ascii", errors="replace")
            case "utf8":
                return data.decode("utf-8", errors="replace")
            case _:
                raise ValueError(f"Unknown encoding: {encoding}")

    def hash_identifier(self, hash_value: str) -> list[dict]:
        h = hash_value.strip()
        length = len(h)
        is_hex = all(c in "0123456789abcdefABCDEF" for c in h) if h else False
        lower_chars = set(h.lower()) if h else set()
        all_hex = all(c in "0123456789abcdef" for c in lower_chars) if lower_chars else False

        results = []

        # Check for bcrypt
        if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
            results.append({
                "hash_type": "bcrypt",
                "length": length,
                "bit_length": 192,
                "format": "$2a/b/y$",
                "example": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
                "confidence": "high"
            })

        # Check for NTLM
        if length == 32 and all_hex:
            results.append({
                "hash_type": "NTLM",
                "length": length,
                "bit_length": 128,
                "format": "32 hex chars (usually uppercase)",
                "example": "B4B9B02E6F09A9BD760F388B67351E2B",
                "confidence": "high"
            })

        # Check for LM hash (format user:RID:hash or just 32 hex chars with possible colon)
        if length == 32 and all_hex:
            results.append({
                "hash_type": "LM Hash",
                "length": length,
                "bit_length": 128,
                "format": "32 hex chars or user:RID:hash",
                "confidence": "medium"
            })

        # Standard hex hash length detection
        spec = {
            8: ("CRC-32", 32, "cksum, ethernet"),
            16: ("CRC-64 / NTLM", 64, "CRC-64"),
            32: ("MD5", 128, "MD5"),
            40: ("SHA-1", 160, "SHA-1"),
            56: ("SHA-224", 224, "SHA-224"),
            64: ("SHA-256", 256, "SHA-256"),
            96: ("SHA-384", 384, "SHA-384"),
            128: ("SHA-512", 512, "SHA-512"),
        }

        if length in spec and all_hex:
            name, bits, fmt = spec[length]
            results.append({
                "hash_type": name,
                "length": length,
                "bit_length": bits,
                "format": fmt,
                "is_hex": True,
                "confidence": "high"
            })
            if length in (32, 40, 64, 128):
                results.append({
                    "hash_type": f"HMAC-{name}",
                    "length": length,
                    "bit_length": bits,
                    "format": "HMAC",
                    "is_hex": True,
                    "confidence": "medium"
                })

        # MD4
        if length == 32 and all_hex:
            results.append({
                "hash_type": "MD4",
                "length": length,
                "bit_length": 128,
                "format": "32 hex chars",
                "confidence": "medium"
            })

        # MD2
        if length == 32 and all_hex:
            results.append({
                "hash_type": "MD2",
                "length": length,
                "bit_length": 128,
                "format": "32 hex chars",
                "confidence": "low"
            })

        # MySQL hash (old: 16 hex, new: 41 hex with leading *)
        if h.startswith("*") and length == 41:
            results.append({
                "hash_type": "MySQL 5.7+",
                "length": length,
                "bit_length": 160,
                "format": "* + 40 hex chars",
                "confidence": "high"
            })

        if length == 41 and h.startswith("*"):
            results.append({
                "hash_type": "MySQL",
                "length": length,
                "bit_length": 160,
                "format": "* + 40 hex chars",
                "confidence": "high"
            })

        # PostgreSQL hash (md5 prefix)
        if h.startswith("md5") and length == 35:
            results.append({
                "hash_type": "PostgreSQL MD5",
                "length": length,
                "bit_length": 128,
                "format": "md5 + 32 hex chars",
                "example": "md5" + "a" * 32,
                "confidence": "high"
            })

        # CRC32 / CRC64 detection
        if length == 8 and all_hex:
            results.append({
                "hash_type": "CRC-32",
                "length": length,
                "bit_length": 32,
                "format": "8 hex chars",
                "confidence": "medium"
            })
        elif length == 16 and all_hex:
            results.append({
                "hash_type": "CRC-64",
                "length": length,
                "bit_length": 64,
                "format": "16 hex chars",
                "confidence": "medium"
            })

        if not results:
            if length == 16 and not all_hex:
                results.append({
                    "hash_type": "CRC-64 / NTLM",
                    "length": length,
                    "bit_length": 64,
                    "is_hex": False,
                    "confidence": "low"
                })
            elif length == 32 and not all_hex:
                results.append({
                    "hash_type": "LM Hash",
                    "length": length,
                    "bit_length": 128,
                    "is_hex": False,
                    "confidence": "low"
                })
            else:
                results.append({
                    "hash_type": "Unknown",
                    "length": length,
                    "bit_length": length * 4 if all_hex else None,
                    "is_hex": all_hex,
                    "confidence": "none"
                })

        # Deduplicate
        seen = set()
        deduped = []
        for r in results:
            key = r["hash_type"]
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        return deduped

    def hex_dump(self, data: str, width: int = 16) -> str:
        raw = data.encode("utf-8") if isinstance(data, str) else data
        lines = []
        for i in range(0, len(raw), width):
            chunk = raw[i:i+width]
            offset = f"{i:08x}"
            hex_parts = []
            for j in range(0, len(chunk), 4):
                group = chunk[j:j+4]
                hex_parts.append(" ".join(f"{b:02x}" for b in group))
            hex_str = "  ".join(hex_parts)

            expected_groups = (width + 3) // 4
            expected_hex_len = expected_groups * 11 - 2
            hex_str = hex_str.ljust(expected_hex_len)

            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset}:  {hex_str}  {ascii_part}")
        return "\n".join(lines)

    def html_encode_full(self, input_str: str) -> str:
        html_table = {
            '"': "&quot;",
            "'": "&#39;",
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            " ": "&nbsp;",
        }
        result = []
        for c in input_str:
            if c in html_table:
                result.append(html_table[c])
            elif ord(c) > 127:
                result.append(f"&#{ord(c)};")
            else:
                result.append(c)
        return "".join(result)

    def html_decode_full(self, input_str: str) -> str:
        s = input_str
        s = re.sub(r"&#x([0-9a-fA-F]+);", lambda m: chr(int(m.group(1), 16)), s)
        s = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), s)
        s = html_mod.unescape(s)
        return s

    def jwt_decode_full(self, token: str) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT: expected 3 parts separated by dots")
        def _b64decode(part: str) -> dict:
            padded = part + "=" * (4 - len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(padded))
        return {
            "header": json.dumps(_b64decode(parts[0]), indent=2),
            "payload": json.dumps(_b64decode(parts[1]), indent=2),
            "signature": parts[2],
        }

    def hash_string(self, input_str: str, algorithm: str) -> str:
        match algorithm:
            case "md5":
                return hashlib.md5(input_str.encode()).hexdigest()
            case "sha1":
                return hashlib.sha1(input_str.encode()).hexdigest()
            case "sha256":
                return hashlib.sha256(input_str.encode()).hexdigest()
            case "sha384":
                return hashlib.sha384(input_str.encode()).hexdigest()
            case "sha512":
                return hashlib.sha512(input_str.encode()).hexdigest()
            case _:
                raise ValueError(f"Unknown hash algorithm: {algorithm}")

    def charset_detect(self, data: str) -> dict:
        raw = data.encode("utf-8") if isinstance(data, str) else data

        if raw[:3] == b"\xef\xbb\xbf":
            return {"charset": "UTF-8 with BOM", "confidence": "high", "method": "BOM detection"}
        if raw[:2] == b"\xff\xfe":
            return {"charset": "UTF-16 LE", "confidence": "high", "method": "BOM detection"}
        if raw[:2] == b"\xfe\xff":
            return {"charset": "UTF-16 BE", "confidence": "high", "method": "BOM detection"}

        try:
            raw.decode("utf-8")
            if all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
                return {"charset": "ASCII", "confidence": "high", "method": "UTF-8 valid, all bytes ASCII"}
            return {"charset": "UTF-8", "confidence": "high", "method": "UTF-8 validation passed"}
        except UnicodeDecodeError:
            pass

        for enc, name in [("latin-1", "ISO-8859-1 (Latin-1)"), ("cp1252", "Windows-1252")]:
            try:
                raw.decode(enc)
                high = sum(1 for b in raw if b > 127)
                if high > 0:
                    return {"charset": name, "confidence": "medium", "method": f"{enc} valid, has high bytes"}
            except Exception:
                continue

        nulls = raw.count(b"\x00")
        if nulls > len(raw) * 0.3:
            even_nulls = sum(1 for i in range(0, len(raw), 2) if raw[i:i+1] == b"\x00")
            odd_nulls = sum(1 for i in range(1, len(raw), 2) if raw[i:i+1] == b"\x00")
            if even_nulls > odd_nulls and even_nulls > len(raw) * 0.3:
                return {"charset": "UTF-16 LE (probable)", "confidence": "low", "method": "null byte pattern analysis"}
            elif odd_nulls > even_nulls and odd_nulls > len(raw) * 0.3:
                return {"charset": "UTF-16 BE (probable)", "confidence": "low", "method": "null byte pattern analysis"}

        return {"charset": "Unknown (possibly binary)", "confidence": "low", "method": "all detection methods exhausted"}

import math
import struct
import re
from collections import Counter
from typing import Optional


class SequencerService:
    def __init__(self):
        self._live_captures: dict[str, dict] = {}

    # --------------------------------------------------------------------------
    # Live capture
    # --------------------------------------------------------------------------

    def start_live_capture(self, session_id: str) -> None:
        if session_id not in self._live_captures:
            self._live_captures[session_id] = {"active": True, "tokens": []}
        else:
            self._live_captures[session_id]["active"] = True

    def stop_live_capture(self, session_id: str) -> None:
        if session_id in self._live_captures:
            self._live_captures[session_id]["active"] = False

    def is_capturing(self, session_id: str) -> bool:
        entry = self._live_captures.get(session_id)
        return entry is not None and entry["active"]

    def capture_token(self, session_id: str, token: str) -> None:
        entry = self._live_captures.get(session_id)
        if entry and entry["active"]:
            entry["tokens"].append(token)

    def get_live_tokens(self, session_id: str) -> list[str]:
        entry = self._live_captures.get(session_id)
        return entry["tokens"] if entry else []

    def clear_live_tokens(self, session_id: str) -> None:
        if session_id in self._live_captures:
            self._live_captures[session_id]["tokens"] = []

    # --------------------------------------------------------------------------
    # Analysis
    # --------------------------------------------------------------------------

    def analyze(self, tokens: list[str]) -> dict:
        if not tokens:
            return {"error": "No tokens provided."}
        if len(tokens) < 100:
            return {"error": "Need at least 100 samples for meaningful analysis."}

        token_length = len(tokens[0])
        all_text = "".join(tokens)
        all_bytes = b"".join(t.encode("utf-8", errors="replace") for t in tokens)

        char_entropy = self._shannon_entropy(all_text)
        bit_entropy = self._shannon_entropy_bytes(all_bytes)
        estimated_bits = char_entropy * token_length

        is_weak = char_entropy < 3.5

        char_freq = dict(Counter(all_text).most_common(50))
        char_freq_list = self._char_freq_list(all_text)

        positional_entropy = self._positional_entropy(tokens, token_length)
        pos_entropy_list = self._positional_entropy_list(tokens, token_length)

        byte_dist = self._byte_distribution(all_bytes)
        byte_dist_list = [{"byte": i, "count": byte_dist[i]} for i in range(256)]

        consec_dupes = self._consecutive_duplicates(tokens)

        autocorr = self._auto_correlation(tokens)

        fips_results = self._fips_140_2_approx(all_bytes)

        longest_run = self._longest_consecutive_run(tokens)
        charset_size = len(set(all_text))
        unique_chars_ratio = charset_size / len(all_text) if all_text else 0
        effective_entropy = char_entropy
        token_type = self._predict_token_type(tokens)
        dup_percentage = round((consec_dupes["count"] / len(tokens)) * 100, 2) if tokens else 0

        return {
            "sample_count": len(tokens),
            "token_length": token_length,
            "char_entropy_bits_per_char": round(char_entropy, 4),
            "estimated_total_bits": round(estimated_bits, 2),
            "bit_entropy": round(bit_entropy, 4),
            "verdict": "WEAK \u2014 token may be predictable" if is_weak else "STRONG \u2014 appears sufficiently random",
            "is_weak": is_weak,
            "unique_tokens": len(set(tokens)),
            "duplicates_found": len(tokens) - len(set(tokens)),
            "character_frequency": char_freq,
            "char_frequencies": char_freq_list,
            "positional_entropy": positional_entropy,
            "positional_entropy_detail": pos_entropy_list,
            "byte_distribution": byte_dist,
            "byte_distribution_detail": byte_dist_list,
            "consecutive_duplicates": consec_dupes,
            "consecutive_duplicate_percentage": dup_percentage,
            "longest_consecutive_run": longest_run,
            "auto_correlation": autocorr,
            "fips_140_2": fips_results,
            "character_set_size": charset_size,
            "unique_chars_ratio": round(unique_chars_ratio, 4),
            "predicted_token_type": token_type,
            "effective_entropy": round(effective_entropy, 4),
        }

    # --------------------------------------------------------------------------
    # NIST FIPS 140-2 Tests
    # --------------------------------------------------------------------------

    def run_fips_140_2(self, tokens: list[str]) -> dict:
        if not tokens:
            return {"error": "No tokens provided."}

        all_bytes = b"".join(t.encode("utf-8", errors="replace") for t in tokens)
        bits = "".join(f"{b:08b}" for b in all_bytes)

        if len(bits) < 20000:
            result = self._run_fips_tests(bits, adjusted=True)
            result["note"] = f"Only {len(bits)} bits available. Tests run with adjusted thresholds."
            result["bits_available"] = len(bits)
        else:
            bits = bits[:20000]
            result = self._run_fips_tests(bits, adjusted=False)
            result["note"] = "Full 20000-bit sequence tested."
            result["bits_available"] = 20000

        return result

    def _run_fips_tests(self, bits: str, adjusted: bool = False) -> dict:
        n = len(bits)
        ones = bits.count("1")

        # 1. Monobit Test
        if adjusted:
            expected = n / 2
            margin = 0.25 * n  # 25% margin for small sequences
            monobit_lower = int(expected - margin)
            monobit_upper = int(expected + margin)
            expected_range = f"{monobit_lower}-{monobit_upper}"
        else:
            monobit_lower = 9725
            monobit_upper = 10275
            expected_range = "9725-10275"

        monobit_pass = monobit_lower <= ones <= monobit_upper

        # 2. Poker Test
        poker_result = self._poker_test(bits, adjusted)

        # 3. Runs Test
        runs_result = self._runs_test(bits, adjusted)

        # 4. Long Run Test
        long_run_result = self._long_run_test(bits, adjusted)

        all_pass = monobit_pass and poker_result["passed"] and runs_result["passed"] and long_run_result["passed"]

        return {
            "tested": True,
            "overall_pass": all_pass,
            "monobit": {
                "name": "Monobit Test",
                "passed": monobit_pass,
                "actual": ones,
                "expected_range": expected_range,
                "description": "Counts 1 bits in the sequence. Should be close to n/2.",
                "bits_tested": n,
            },
            "poker": poker_result,
            "runs": runs_result,
            "long_run": long_run_result,
        }

    def _poker_test(self, bits: str, adjusted: bool) -> dict:
        n = len(bits)
        block_size = 4
        num_blocks = n // block_size
        if num_blocks < 100:
            num_blocks = max(1, num_blocks)

        counts = [0] * 16
        for i in range(num_blocks):
            block = bits[i * block_size:(i + 1) * block_size]
            val = int(block, 2)
            counts[val] += 1

        if num_blocks > 0:
            X = (16.0 / num_blocks) * sum(c * c for c in counts) - num_blocks
        else:
            X = 0.0

        if adjusted:
            lower = 0.5
            upper = max(100.0, num_blocks * 0.5)
        else:
            lower = 1.03
            upper = 57.4

        passed = lower < X < upper

        return {
            "name": "Poker Test",
            "passed": passed,
            "actual": round(X, 4),
            "expected_range": f"{lower}-{upper}",
            "description": "Divides into 4-bit segments, computes chi-square statistic X.",
            "blocks_tested": num_blocks,
            "block_size": 4,
        }

    def _runs_test(self, bits: str, adjusted: bool) -> dict:
        n = len(bits)
        runs = []
        if not bits:
            return {"name": "Runs Test", "passed": False, "actual": {}, "expected_range": {}, "description": "No bits to test."}

        current_run = 1
        for i in range(1, len(bits)):
            if bits[i] == bits[i - 1]:
                current_run += 1
            else:
                runs.append(current_run)
                current_run = 1
        runs.append(current_run)

        run_counts = Counter(runs)
        intervals = {
            1: (2343, 2657),
            2: (1135, 1365),
            3: (542, 708),
            4: (251, 373),
            5: (111, 201),
            6: (111, 201),
        }

        if adjusted:
            scale = n / 20000.0
            intervals = {k: (max(1, int(v[0] * scale)), max(1, int(v[1] * scale))) for k, v in intervals.items()}

        run_details = []
        all_pass = True
        for run_len in sorted(set(runs)):
            count = run_counts[run_len]
            length_key = min(run_len, 6)
            if length_key in intervals:
                lo, hi = intervals[length_key]
                passed = lo <= count <= hi
                if not passed:
                    all_pass = False
                run_details.append({
                    "run_length": run_len,
                    "count": count,
                    "expected_range": f"{lo}-{hi}" if length_key in intervals else "N/A",
                    "passed": passed,
                })

        return {
            "name": "Runs Test",
            "passed": all_pass,
            "actual": run_details,
            "description": "Counts runs of consecutive identical bits. Checks each run length against expected intervals.",
            "total_runs": len(runs),
        }

    def _long_run_test(self, bits: str, adjusted: bool) -> dict:
        if not bits:
            return {"name": "Long Run Test", "passed": False, "actual": 0, "expected_max": 0}

        current_run = 1
        longest = 0
        for i in range(1, len(bits)):
            if bits[i] == bits[i - 1]:
                current_run += 1
            else:
                longest = max(longest, current_run)
                current_run = 1
        longest = max(longest, current_run)

        if adjusted:
            max_allowed = max(26, int(26 * len(bits) / 20000.0))
        else:
            max_allowed = 25

        passed = longest <= max_allowed

        return {
            "name": "Long Run Test",
            "passed": passed,
            "actual": longest,
            "expected_max": max_allowed,
            "description": "Checks for any run of 26+ consecutive identical bits.",
        }

    def _fips_140_2_approx(self, data: bytes) -> dict:
        if len(data) < 20000:
            return {"tested": False, "reason": "Need >= 20000 bytes for FIPS 140-2 approximation"}

        bits = "".join(f"{b:08b}" for b in data[:2500])
        n = len(bits)
        if n < 20000:
            bits = bits.ljust(20000, "0")
            n = 20000
        bits = bits[:20000]

        ones = bits.count("1")
        monobit_pass = 9654 <= ones <= 10346

        runs = []
        current_run = 1
        for i in range(1, len(bits)):
            if bits[i] == bits[i - 1]:
                current_run += 1
            else:
                runs.append((bits[i - 1], current_run))
                current_run = 1
        runs.append((bits[-1], current_run))

        long_run = max(r[1] for r in runs)
        long_run_pass = long_run <= 34

        return {
            "tested": True,
            "monobit": {"ones": ones, "pass": monobit_pass},
            "longest_run": {"length": long_run, "pass": long_run_pass},
            "runs_count": len(runs),
        }

    # --------------------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------------------

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        freq = Counter(data)
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def _shannon_entropy_bytes(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = Counter(data)
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def _positional_entropy(self, tokens: list[str], length: int) -> list[float]:
        entropies = []
        for pos in range(length):
            col = [t[pos] if pos < len(t) else "" for t in tokens]
            col_str = "".join(col)
            entropies.append(round(self._shannon_entropy(col_str), 4))
        return entropies

    def _positional_entropy_list(self, tokens: list[str], length: int) -> list[dict]:
        result = []
        for pos in range(length):
            col = [t[pos] if pos < len(t) else "" for t in tokens]
            col_str = "".join(col)
            result.append({"position": pos, "entropy": round(self._shannon_entropy(col_str), 4)})
        return result

    def _char_freq_list(self, data: str) -> list[dict]:
        if not data:
            return []
        freq = Counter(data)
        n = len(data)
        sorted_chars = sorted(freq.items(), key=lambda x: (-x[1], x[0]))
        return [
            {"char": repr(c) if c in " \t\n\r" else c, "count": count, "percentage": round(count / n * 100, 4)}
            for c, count in sorted_chars
        ]

    def _byte_distribution(self, data: bytes) -> list[int]:
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        return counts

    def _consecutive_duplicates(self, tokens: list[str]) -> dict:
        count = 0
        positions = []
        for i in range(1, len(tokens)):
            if tokens[i] == tokens[i - 1]:
                count += 1
                if len(positions) < 10:
                    positions.append(i)
        return {"count": count, "sample_positions": positions}

    def _longest_consecutive_run(self, tokens: list[str]) -> dict:
        if not tokens:
            return {"length": 0, "value": None}
        max_run = 1
        current_run = 1
        best_val = tokens[0]
        for i in range(1, len(tokens)):
            if tokens[i] == tokens[i - 1]:
                current_run += 1
                if current_run > max_run:
                    max_run = current_run
                    best_val = tokens[i]
            else:
                current_run = 1
        return {"length": max_run, "value": best_val}

    def _auto_correlation(self, tokens: list[str]) -> dict:
        n = len(tokens)
        if n < 2:
            return {"lag_1": 0.0, "note": "insufficient samples"}

        numeric = [sum(ord(c) for c in t) for t in tokens]
        mean = sum(numeric) / n
        var = sum((x - mean) ** 2 for x in numeric) / n
        if var == 0:
            return {"lag_1": 0.0, "note": "zero variance"}

        lag_1_num = sum((numeric[i] - mean) * (numeric[i + 1] - mean) for i in range(n - 1))
        lag_1_den = (n - 1) * var
        lag_1 = lag_1_num / lag_1_den if lag_1_den != 0 else 0.0

        anomaly = abs(lag_1) > 0.3

        return {
            "lag_1": round(lag_1, 4),
            "anomaly_detected": anomaly,
            "note": "High autocorrelation suggests predictability" if anomaly else "No significant autocorrelation"
        }

    def _predict_token_type(self, tokens: list[str]) -> str:
        if not tokens:
            return "Unknown"
        sample = tokens[0]

        # UUID
        uuid_pattern = re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", sample, re.I)
        if uuid_pattern:
            return "UUID"

        # JWT
        if sample.count(".") == 2:
            try:
                import base64
                parts = sample.split(".")
                for p in parts[:2]:
                    padded = p + "=" * (4 - len(p) % 4)
                    base64.urlsafe_b64decode(padded)
                return "JWT"
            except Exception:
                pass

        # Session ID (base64)
        if re.match(r"^[A-Za-z0-9+/=]+$", sample) and len(sample) % 4 == 0:
            try:
                import base64
                decoded = base64.b64decode(sample)
                if len(decoded) >= 8:
                    return "Session ID (base64)"
            except Exception:
                pass

        # Numeric
        if re.match(r"^\d+$", sample):
            return "Numeric"

        # Hex
        if re.match(r"^[0-9a-fA-F]+$", sample) and len(sample) % 2 == 0:
            return "Hex"

        # Alphanumeric
        if re.match(r"^[A-Za-z0-9]+$", sample):
            return "Alphanumeric"

        return "Unknown"

    # --------------------------------------------------------------------------
    # Chi-Square distribution analysis
    # --------------------------------------------------------------------------

    def chi_square_analysis(self, tokens: list[str]) -> dict:
        if not tokens:
            return {"error": "No tokens provided."}
        all_text = "".join(tokens)
        n = len(all_text)
        if n == 0:
            return {"error": "Empty tokens."}

        observed = Counter(all_text)
        charset_size = len(observed)
        if charset_size == 0:
            return {"error": "No characters to analyze."}

        expected = n / charset_size
        chi_sq = sum((c - expected) ** 2 / expected for c in observed.values())
        df = charset_size - 1
        significance = self._chi_square_p_value(chi_sq, df)

        return {
            "chi_square_statistic": round(chi_sq, 4),
            "degrees_of_freedom": df,
            "p_value": round(significance, 6),
            "charset_size": charset_size,
            "sample_size": n,
            "expected_per_char": round(expected, 2),
            "is_significant": significance < 0.05,
            "interpretation": (
                "Distribution differs from uniform (possible predictability)"
                if significance < 0.05
                else "Distribution consistent with uniform random"
            ),
        }

    def _chi_square_p_value(self, chi_sq: float, df: int) -> float:
        if df <= 0 or chi_sq < 0:
            return 1.0
        return 1.0 - self._gammainc(df / 2.0, chi_sq / 2.0)

    def _gammainc(self, a: float, x: float) -> float:
        if x <= 0:
            return 0.0
        if a <= 0:
            return 1.0
        from math import exp, log, gamma
        if x < a + 1:
            s = 1.0
            t = 1.0
            for k in range(1, 300):
                t *= x / (a + k)
                s += t
                if abs(t) < 1e-15:
                    break
            result = s * exp(-x + a * log(x) - log(gamma(a)))
            return max(0.0, min(1.0, result))
        else:
            f = 1.0 / (x - a + 1.0 + (a + 1.0) / (x + 2.0))
            if f <= 0:
                f = 1e-30
            c = 1.0
            d = 1.0 / (x - a + 1.0)
            if d <= 0:
                d = 1e-30
            for k in range(1, 200):
                numerator = -k * (k - a)
                d = x + 2 * k + numerator * d
                if abs(d) < 1e-30:
                    d = 1e-30
                c = x + 2 * k + numerator / c
                if abs(c) < 1e-30:
                    c = 1e-30
                d = 1.0 / d
                delta = c * d
                f *= delta
                if abs(delta - 1.0) < 1e-15:
                    break
            result = 1.0 - exp(-x + a * log(x) - log(gamma(a))) * f
            return max(0.0, min(1.0, result))

    # --------------------------------------------------------------------------
    # Monte Carlo simulation
    # --------------------------------------------------------------------------

    def monte_carlo_simulation(self, tokens: list[str], trials: int = 1000) -> dict:
        if not tokens or len(tokens) < 10:
            return {"error": "Need at least 10 tokens for Monte Carlo simulation."}

        import random
        numeric = [sum(ord(c) for c in t) for t in tokens]
        sample = numeric[:200]
        n = len(sample)
        if n < 2:
            return {"error": "Insufficient samples."}

        mean = sum(sample) / n
        std = (sum((x - mean) ** 2 for x in sample) / n) ** 0.5 or 1

        matches = 0
        for _ in range(trials):
            simulated = [random.gauss(mean, std) for _ in range(n)]
            sim_mean = sum(simulated) / n
            sim_std = (sum((x - sim_mean) ** 2 for x in simulated) / n) ** 0.5 or 1
            if abs(sim_mean - mean) / std < 0.1 and abs(sim_std - std) / std < 0.1:
                matches += 1

        predictability = 1.0 - (matches / trials)
        return {
            "trials": trials,
            "sample_size": n,
            "mean": round(mean, 4),
            "std_dev": round(std, 4),
            "matches": matches,
            "predictability_score": round(predictability, 6),
            "interpretation": (
                "LOW predictability (good randomness)"
                if predictability > 0.95
                else "MEDIUM predictability"
                if predictability > 0.7
                else "HIGH predictability (weak token)"
            ),
        }

    # --------------------------------------------------------------------------
    # Bit-level FIPS analysis
    # --------------------------------------------------------------------------

    def bit_analysis(self, tokens: list[str]) -> dict:
        if not tokens:
            return {"error": "No tokens provided."}
        all_bytes = b"".join(t.encode("utf-8", errors="replace") for t in tokens)
        bits = "".join(f"{b:08b}" for b in all_bytes)
        n = len(bits)
        if n < 4:
            return {"error": "Need at least 4 bits."}

        ones = bits.count("1")
        zeros = bits.count("0")
        zero_runs = self._count_runs(bits, "0")
        one_runs = self._count_runs(bits, "1")

        consec_zeros = self._longest_consecutive_bits(bits, "0")
        consec_ones = self._longest_consecutive_bits(bits, "1")

        block_entropy = self._block_entropy(bits, block_size=4)
        byte_entropy = self._shannon_entropy_bytes(all_bytes)

        bit_freq = [bits.count(str(b)) for b in range(2)]

        return {
            "total_bits": n,
            "ones": ones,
            "zeros": zeros,
            "ones_ratio": round(ones / n, 6),
            "zero_runs": zero_runs,
            "one_runs": one_runs,
            "longest_zero_run": consec_zeros,
            "longest_one_run": consec_ones,
            "block_entropy_4bit": round(block_entropy, 4),
            "byte_entropy": round(byte_entropy, 4),
            "bit_frequency": {"0": bit_freq[0], "1": bit_freq[1]},
            "balance": round(1.0 - abs(0.5 - ones / n) * 2, 4),
        }

    def _count_runs(self, bits: str, target: str) -> int:
        count = 0
        i = 0
        while i < len(bits):
            if bits[i] == target:
                count += 1
                while i < len(bits) and bits[i] == target:
                    i += 1
            else:
                i += 1
        return count

    def _longest_consecutive_bits(self, bits: str, target: str) -> int:
        current = 0
        longest = 0
        for b in bits:
            if b == target:
                current += 1
                longest = max(longest, current)
            else:
                current = 0
        return longest

    def _block_entropy(self, bits: str, block_size: int = 4) -> float:
        blocks = []
        for i in range(0, len(bits) - block_size + 1, block_size):
            blocks.append(bits[i:i + block_size])
        if not blocks:
            return 0.0
        return self._shannon_entropy("".join(blocks))

    # --------------------------------------------------------------------------
    # Chart data generation
    # --------------------------------------------------------------------------

    def generate_chart_data(self, tokens: list[str]) -> dict:
        if not tokens:
            return {"error": "No tokens provided."}
        analysis = self.analyze(tokens)

        freq_labels = []
        freq_values = []
        for item in analysis.get("char_frequencies", [])[:15]:
            freq_labels.append(repr(item["char"]) if len(item["char"]) == 1 else item["char"])
            freq_values.append(item["count"])

        pos_labels = []
        pos_values = []
        for item in analysis.get("positional_entropy_detail", [])[:50]:
            pos_labels.append(str(item["position"]))
            pos_values.append(item["entropy"])

        byte_dist = analysis.get("byte_distribution_detail", [])[:256]
        byte_labels = [str(b["byte"]) for b in byte_dist if b["byte"] < 256]
        byte_values = [b["count"] for b in byte_dist if b["byte"] < 256]

        return {
            "char_frequency": {"labels": freq_labels, "values": freq_values},
            "positional_entropy": {"labels": pos_labels, "values": pos_values},
            "byte_distribution": {"labels": byte_labels, "values": byte_values},
            "summary": {
                "entropy": analysis.get("char_entropy_bits_per_char", 0),
                "sample_count": len(tokens),
                "unique_tokens": analysis.get("unique_tokens", 0),
                "token_length": analysis.get("token_length", 0),
                "verdict": analysis.get("verdict", ""),
            },
        }

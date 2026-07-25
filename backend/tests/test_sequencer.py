import pytest
from modules.sequencer.service import SequencerService


@pytest.fixture
def svc():
    return SequencerService()


class TestAnalyze:
    def test_empty_input_returns_error(self, svc):
        result = svc.analyze([])
        assert "error" in result
        assert "No tokens" in result["error"]

    def test_single_token_insufficient(self, svc):
        result = svc.analyze(["abc123"])
        assert "error" in result
        assert "100 samples" in result["error"]

    def test_99_tokens_insufficient(self, svc):
        tokens = ["token"] * 99
        result = svc.analyze(tokens)
        assert "error" in result

    def test_identical_tokens_low_entropy(self, svc):
        tokens = ["aaaaaa"] * 200
        result = svc.analyze(tokens)
        assert "error" not in result
        assert result["is_weak"] is True
        assert "WEAK" in result["verdict"]
        assert result["unique_tokens"] == 1
        assert result["duplicates_found"] == 199

    def test_random_tokens_high_entropy(self, svc):
        tokens = [__import__("secrets").token_hex(16) for _ in range(200)]
        result = svc.analyze(tokens)
        assert "error" not in result
        assert result["char_entropy_bits_per_char"] > 3.5
        assert result["is_weak"] is False
        assert "STRONG" in result["verdict"]
        assert result["sample_count"] == 200
        assert result["token_length"] == 32

    def test_analyze_struct(self, svc):
        tokens = ["abc123def456"] * 200
        result = svc.analyze(tokens)
        assert "sample_count" in result
        assert "token_length" in result
        assert "char_entropy_bits_per_char" in result
        assert "estimated_total_bits" in result
        assert "bit_entropy" in result
        assert "verdict" in result
        assert "is_weak" in result
        assert "unique_tokens" in result
        assert "duplicates_found" in result
        assert "character_frequency" in result
        assert "positional_entropy" in result
        assert isinstance(result["positional_entropy"], list)
        assert "byte_distribution" in result
        assert isinstance(result["byte_distribution"], list)
        assert len(result["byte_distribution"]) == 256
        assert "consecutive_duplicates" in result
        assert "auto_correlation" in result
        assert "fips_140_2" in result

    def test_consecutive_duplicates_counted(self, svc):
        tokens = ["abcdef"] * 200
        result = svc.analyze(tokens)
        assert result["consecutive_duplicates"]["count"] == 199

    def test_auto_correlation_identical_tokens(self, svc):
        tokens = ["abcdef"] * 200
        result = svc.analyze(tokens)
        assert "lag_1" in result["auto_correlation"]


class TestLiveCapture:
    def test_start_stop_capture(self, svc):
        svc.start_live_capture("session1")
        assert svc.is_capturing("session1") is True
        svc.stop_live_capture("session1")
        assert svc.is_capturing("session1") is False

    def test_capture_token_when_active(self, svc):
        svc.start_live_capture("session1")
        svc.capture_token("session1", "tok1")
        svc.capture_token("session1", "tok2")
        assert svc.get_live_tokens("session1") == ["tok1", "tok2"]

    def test_does_not_capture_when_inactive(self, svc):
        svc.capture_token("session1", "tok1")
        assert svc.get_live_tokens("session1") == []

    def test_clear_tokens(self, svc):
        svc.start_live_capture("session1")
        svc.capture_token("session1", "tok1")
        svc.clear_live_tokens("session1")
        assert svc.get_live_tokens("session1") == []

    def test_is_capturing_unknown_session(self, svc):
        assert svc.is_capturing("nonexistent") is False

    def test_get_live_tokens_unknown_session(self, svc):
        assert svc.get_live_tokens("nonexistent") == []

    def test_restart_live_capture(self, svc):
        svc.start_live_capture("session1")
        svc.capture_token("session1", "tok1")
        svc.start_live_capture("session1")
        assert svc.is_capturing("session1") is True
        assert svc.get_live_tokens("session1") == ["tok1"]


class TestHelpers:
    def test_shannon_entropy_empty_string(self, svc):
        assert svc._shannon_entropy("") == 0.0

    def test_shannon_entropy_bytes_empty(self, svc):
        assert svc._shannon_entropy_bytes(b"") == 0.0

    def test_positional_entropy_returns_per_position(self, svc):
        tokens = ["ab", "ab", "cd"]
        result = svc._positional_entropy(tokens, 2)
        assert len(result) == 2
        assert all(isinstance(e, float) for e in result)

    def test_fips_not_enough_data(self, svc):
        result = svc._fips_140_2_approx(b"small")
        assert result["tested"] is False
        assert "20000 bytes" in result["reason"]


class TestChiSquare:
    def test_chi_square_empty(self, svc):
        result = svc.chi_square_analysis([])
        assert "error" in result

    def test_chi_square_uniform(self, svc):
        tokens = ["abcdefghijklmnopqrstuvwxyz"] * 100
        result = svc.chi_square_analysis(tokens)
        assert "error" not in result
        assert result["chi_square_statistic"] >= 0
        assert result["degrees_of_freedom"] > 0
        assert result["p_value"] > 0

    def test_chi_square_repeated(self, svc):
        tokens = ["aaab"] * 200
        result = svc.chi_square_analysis(tokens)
        assert result["is_significant"] is True

    def test_chi_square_p_value_edges(self, svc):
        assert svc._chi_square_p_value(-1, 1) == 1.0
        assert svc._chi_square_p_value(0, 0) == 1.0
        assert svc._chi_square_p_value(10, 5) > 0


class TestMonteCarlo:
    def test_monte_carlo_empty(self, svc):
        result = svc.monte_carlo_simulation([])
        assert "error" in result

    def test_monte_carlo_identical(self, svc):
        tokens = ["aaaaaa"] * 50
        result = svc.monte_carlo_simulation(tokens, trials=50)
        assert "error" not in result
        assert result["trials"] == 50
        assert result["predictability_score"] is not None

    def test_monte_carlo_random(self, svc):
        tokens = [__import__("secrets").token_hex(16) for _ in range(50)]
        result = svc.monte_carlo_simulation(tokens, trials=50)
        assert "error" not in result
        assert result["predictability_score"] > 0.5


class TestBitAnalysis:
    def test_bit_analysis_empty(self, svc):
        result = svc.bit_analysis([])
        assert "error" in result

    def test_bit_analysis_identical(self, svc):
        tokens = ["aaaaaa"] * 200
        result = svc.bit_analysis(tokens)
        assert "error" not in result
        assert result["total_bits"] > 0
        assert "ones" in result
        assert "zeros" in result
        assert "balance" in result
        assert "block_entropy_4bit" in result

    def test_bit_analysis_random(self, svc):
        tokens = [__import__("secrets").token_hex(16) for _ in range(200)]
        result = svc.bit_analysis(tokens)
        assert "error" not in result
        assert result["ones"] + result["zeros"] == result["total_bits"]
        assert result["byte_entropy"] > 3.0

    def test_count_runs(self, svc):
        assert svc._count_runs("111000111", "1") == 2
        assert svc._count_runs("111000111", "0") == 1
        assert svc._count_runs("101010", "1") == 3
        assert svc._count_runs("000", "1") == 0

    def test_longest_consecutive_bits(self, svc):
        assert svc._longest_consecutive_bits("111000111", "1") == 3
        assert svc._longest_consecutive_bits("110011", "0") == 2
        assert svc._longest_consecutive_bits("000", "1") == 0

    def test_block_entropy(self, svc):
        assert svc._block_entropy("00001111", 4) == 1.0


class TestChartData:
    def test_chart_data_empty(self, svc):
        result = svc.generate_chart_data([])
        assert "error" in result

    def test_chart_data_structure(self, svc):
        tokens = ["abcdefgh"] * 200
        result = svc.generate_chart_data(tokens)
        assert "error" not in result
        assert "char_frequency" in result
        assert "positional_entropy" in result
        assert "byte_distribution" in result
        assert "summary" in result
        assert "entropy" in result["summary"]
        assert "sample_count" in result["summary"]
        assert "verdict" in result["summary"]
        assert isinstance(result["char_frequency"]["labels"], list)
        assert isinstance(result["char_frequency"]["values"], list)
        assert isinstance(result["positional_entropy"]["labels"], list)
        assert isinstance(result["positional_entropy"]["values"], list)

    def test_chart_data_random(self, svc):
        tokens = [__import__("secrets").token_hex(16) for _ in range(200)]
        result = svc.generate_chart_data(tokens)
        assert "error" not in result
        assert len(result["byte_distribution"]["labels"]) == 256

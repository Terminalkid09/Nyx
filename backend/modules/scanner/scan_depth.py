"""Scanner depth profiles.

Controls the intensity of active scans via named profiles:

  - ``fast``     — quick recon: only fast, non-intrusive checks. No blind,
                   time-based, or OAST. For initial triage and large scopes.
  - ``balanced`` — default: most checks, but time/blind/OAST payloads are
                   limited. Good signal-to-noise for normal engagements.
  - ``deep``     — full audit: every check with maximum payload counts,
                   including boolean-blind, time-based, and OAST. For
                   high-value targets and compliance testing.

The depth is passed through ``run_checks(..., depth="balanced")`` and filters
the check set + caps payload counts. It does NOT change check logic — it only
decides what runs and how hard.
"""
from dataclasses import dataclass

# Check name patterns (substring match) classified by cost.
# "heavy" checks make many requests or wait on timers; they only run in
# "balanced" (reduced) or "deep" (full) profiles.
_HEAVY_CHECK_PATTERNS: tuple[str, ...] = (
    "time_blind",      # waits on SLEEP payloads
    "sqli_blind",      # paired differential requests
    "oast",            # collaborator polling
    "race",            # many concurrent requests
    "log4shell",       # multiple JNDI payloads
    "brute",           # brute-force style
    "fuzz",            # fuzzing
    "enum",            # enumeration (wordlists)
    "spel",            # deep template injection
    "ssti_blind",      # blind template injection
)

# Checks to always skip in "fast" mode (too slow/intrusive for triage).
_FAST_SKIP_PATTERNS: tuple[str, ...] = _HEAVY_CHECK_PATTERNS + (
    "deserialization",
    "smuggling",
    "cache_poison",
)


@dataclass
class ScanDepth:
    name: str
    # Maximum number of payloads per parameter for heavy checks
    max_payloads_per_param: int = 20
    # Run heavy (slow/blind/OAST) checks at all
    include_heavy: bool = True

    def skip_check(self, check_name: str) -> bool:
        """Return True if this check should be skipped for this depth."""
        if not self.include_heavy:
            return any(p in check_name for p in _FAST_SKIP_PATTERNS)
        return False


# Named profiles
_DEPTHS: dict[str, ScanDepth] = {
    "fast": ScanDepth(name="fast", max_payloads_per_param=5, include_heavy=False),
    "balanced": ScanDepth(name="balanced", max_payloads_per_param=15, include_heavy=True),
    "deep": ScanDepth(name="deep", max_payloads_per_param=50, include_heavy=True),
}

# Default profile name
DEFAULT_DEPTH = "balanced"


def get_depth(name: str | None) -> ScanDepth:
    """Return the ScanDepth for a named profile (default: balanced)."""
    if not name:
        return _DEPTHS[DEFAULT_DEPTH]
    return _DEPTHS.get(name.lower(), _DEPTHS[DEFAULT_DEPTH])


def list_depths() -> list[str]:
    """Return the available profile names."""
    return list(_DEPTHS.keys())
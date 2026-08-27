"""MAC OUI → vendor lookup with in-memory cache.

Strategy (in order):
1. In-memory cache (prefix → vendor, 24-h TTL) — zero-latency repeat queries
2. If MAC is locally administered (randomised), fall back to hostname heuristics
3. api.macvendors.com  (free, no key, 1 req/s rate-limit)
4. maclookup.app       (free alternative, slightly different DB)
5. None               — unknown vendor, caller may show "Unknown"

All network calls are blocking (designed to run in a thread via
``asyncio.to_thread``); no asyncio event loop is needed here.
"""

from __future__ import annotations

import logging
import re
import time
import urllib.request
import urllib.error
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory cache: { oui_prefix: (vendor_str, expires_at) }
# OUI prefix is the first 8 characters of a normalised MAC (xx:xx:xx).
# ---------------------------------------------------------------------------
_CACHE: dict[str, tuple[str, float]] = {}
_CACHE_TTL = 86_400.0  # 24 hours

# ---------------------------------------------------------------------------
# Hostname-based heuristics: regex → display name.
# Covers devices with randomised / unregistered MACs (phones in privacy mode,
# VMs, etc.) that would never match an OUI database.
# ---------------------------------------------------------------------------
_HOSTNAME_PATTERNS: list[tuple[str, str]] = [
    # Samsung Galaxy models
    (r"(?i)\bS2[0-9]\b",       "Samsung Galaxy S"),
    (r"(?i)\bS[1-9][0-9]?\b",  "Samsung Galaxy S"),
    (r"(?i)\bA[0-9]{2}\b",     "Samsung Galaxy A"),
    (r"(?i)\bGalaxy\b",        "Samsung Galaxy"),
    (r"(?i)\bSamsung\b",       "Samsung"),
    # Apple
    (r"(?i)\biPhone\b",        "Apple iPhone"),
    (r"(?i)\biPad\b",          "Apple iPad"),
    (r"(?i)\biMac\b",          "Apple iMac"),
    (r"(?i)\bMacBook\b",       "Apple MacBook"),
    (r"(?i)\bApple\b",         "Apple"),
    # Google
    (r"(?i)\bPixel\b",         "Google Pixel"),
    (r"(?i)\bNexus\b",         "Google Nexus"),
    # Xiaomi
    (r"(?i)\bRedmi\b",         "Xiaomi Redmi"),
    (r"(?i)\bPOCO\b",          "Xiaomi POCO"),
    (r"(?i)\bXiaomi\b",        "Xiaomi"),
    (r"(?i)\bmihome\b",        "Xiaomi Mi Home"),
    # Other Android
    (r"(?i)\bOnePlus\b",       "OnePlus"),
    (r"(?i)\bHuawei\b",        "Huawei"),
    (r"(?i)\bHonor\b",         "Honor"),
    (r"(?i)\bOppo\b",          "OPPO"),
    (r"(?i)\bVivo\b",          "vivo"),
    (r"(?i)\bMotorola\b",      "Motorola"),
    # IoT / smart home
    (r"(?i)\bRoomba\b",        "iRobot Roomba"),
    (r"(?i)\bPetkit\b",        "Petkit"),
    (r"(?i)\bModemTIM\b",      "TIM Modem (Vantiva)"),
    # Networking
    (r"(?i)\bTP[-_]?Link\b",   "TP-Link"),
    (r"(?i)\bNetgear\b",       "Netgear"),
    (r"(?i)\bCisco\b",         "Cisco"),
    (r"(?i)\bFritzBox\b",      "AVM FRITZ!Box"),
    (r"(?i)\bASUS\b",          "ASUS"),
    # Gaming
    (r"(?i)\bNintendo\b",      "Nintendo"),
    (r"(?i)\bPlayStation\b",   "Sony PlayStation"),
    (r"(?i)\bXbox\b",          "Microsoft Xbox"),
]

_compiled_hostname_patterns: list[tuple[re.Pattern, str]] | None = None


def _get_compiled_patterns() -> list[tuple[re.Pattern, str]]:
    global _compiled_hostname_patterns
    if _compiled_hostname_patterns is None:
        _compiled_hostname_patterns = [
            (re.compile(pat), name) for pat, name in _HOSTNAME_PATTERNS
        ]
    return _compiled_hostname_patterns


def _is_locally_administered(mac: str) -> bool:
    """Return True if the MAC has the LA bit set (randomised / private MAC)."""
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False


def _normalise_mac(mac: str) -> str:
    """Return the OUI prefix in ``xx:xx:xx`` form (lowercase)."""
    # Accept both colon-separated and dash-separated formats
    mac = mac.lower().replace("-", ":").strip()
    return mac[:8]


def _lookup_macvendors_com(mac: str) -> Optional[str]:
    """Query api.macvendors.com (free, no API key, 1 req/s rate limit)."""
    try:
        url = f"https://api.macvendors.com/{mac}"
        req = urllib.request.Request(url, headers={"User-Agent": "Nyx/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                vendor = resp.read().decode("utf-8", errors="replace").strip()
                if vendor and "errors" not in vendor.lower():
                    return vendor
    except urllib.error.HTTPError as e:
        if e.code == 404:
            logger.debug("macvendors.com: OUI not found for %s", mac)
        else:
            logger.debug("macvendors.com error %d for %s", e.code, mac)
    except Exception as e:
        logger.debug("macvendors.com lookup failed for %s: %s", mac, e)
    return None


def _lookup_maclookup_app(mac: str) -> Optional[str]:
    """Fallback query to maclookup.app (free, different OUI database)."""
    try:
        # Use the simplified endpoint that returns plain text
        url = f"https://maclookup.app/api/v2/macs/{mac}"
        req = urllib.request.Request(url, headers={"User-Agent": "Nyx/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                import json
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                vendor = data.get("company") or data.get("vendorName") or data.get("vendor")
                if vendor:
                    return vendor.strip()
    except Exception as e:
        logger.debug("maclookup.app lookup failed for %s: %s", mac, e)
    return None


def lookup_vendor_from_hostname(hostname: Optional[str]) -> Optional[str]:
    """Guess the vendor from the device hostname using regex heuristics."""
    if not hostname:
        return None
    for pattern, name in _get_compiled_patterns():
        if pattern.search(hostname):
            return name
    return None


def lookup_vendor(mac: str, hostname: Optional[str] = None) -> Optional[str]:
    """Return the vendor name for a given MAC address.

    Checks the in-memory cache first, then queries online OUI databases.
    For locally-administered (randomised) MACs, falls back to hostname heuristics.

    This function is **blocking** — run it in a thread when calling from async code:
        ``vendor = await asyncio.to_thread(lookup_vendor, mac, hostname)``
    """
    if not mac:
        return None

    prefix = _normalise_mac(mac)

    # --- Cache hit ---
    cached = _CACHE.get(prefix)
    if cached is not None:
        vendor, expires = cached
        if time.monotonic() < expires:
            return vendor or None
        # Expired — remove and re-query
        del _CACHE[prefix]

    # --- Locally administered (randomised) MAC ---
    if _is_locally_administered(mac):
        vendor = lookup_vendor_from_hostname(hostname)
        # Cache even a None result so we don't hammer the hostname heuristics
        _CACHE[prefix] = (vendor or "", time.monotonic() + _CACHE_TTL)
        logger.debug("Randomised MAC %s → hostname heuristic → %s", mac, vendor)
        return vendor

    # --- Online OUI lookup (primary) ---
    vendor = _lookup_macvendors_com(mac)

    # --- Online OUI lookup (fallback) ---
    if not vendor:
        vendor = _lookup_maclookup_app(mac)

    # --- Last resort: hostname heuristic ---
    if not vendor:
        vendor = lookup_vendor_from_hostname(hostname)

    _CACHE[prefix] = (vendor or "", time.monotonic() + _CACHE_TTL)
    logger.debug("Vendor lookup %s → %s", mac, vendor)
    return vendor


async def lookup_vendor_async(mac: str, hostname: Optional[str] = None) -> Optional[str]:
    """Async wrapper around :func:`lookup_vendor` for use in FastAPI routes."""
    import asyncio
    return await asyncio.to_thread(lookup_vendor, mac, hostname)


def cache_stats() -> dict:
    """Return cache statistics for diagnostics."""
    now = time.monotonic()
    total = len(_CACHE)
    alive = sum(1 for _, (_, exp) in _CACHE.items() if exp > now)
    return {"total": total, "alive": alive, "expired": total - alive}

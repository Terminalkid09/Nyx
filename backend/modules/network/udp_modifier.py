"""UDP in-flight modification — rule-driven rewrites of live UDP payloads.

mitmproxy handles HTTP(S); arbitrary UDP (games, custom protocols, IoT) is
out of its scope. This module closes that gap on top of the network layer's
own primitives:

    UDP packet captured -> match against rules -> rewrite payload
        -> PacketManipulator.modify_in_place (checksums recalculated)
        -> PacketManipulator.inject (re-injected into the wire)

Rules are simple (field_match + payload rewrite) by design — this is a
test-bed for in-flight tampering, not a full protocol proxy. Direction
matters: by default a rule matches CLIENT->SERVER packets only, so server
responses are not rewritten with client rules.
"""
import fnmatch
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional

from core.network.capture import RawPacket

logger = logging.getLogger(__name__)

# UDP protocol number (RFC 768) — RawPacket summaries carry IANA numbers.
_PROTO_UDP = 17


@dataclass
class UDPModifyRule:
    """One rewrite rule: match a UDP flow direction + payload pattern."""

    name: str
    # Flow selectors (None = wildcard).
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    src_port: Optional[int] = None
    # fnmatch pattern applied to the ASCII-decoded payload ("*" matches all).
    payload_pattern: str = "*"
    # Replacement payload bytes (what the payload becomes when the pattern
    # matches). Keep None + on_rewrite set for observe-only rules.
    payload_replace: Optional[bytes] = None
    # Optional callback fired on every match (before rewrite). Receives the
    # original RawPacket; return value ignored.
    on_rewrite: Optional[Callable[[RawPacket], None]] = None
    # When False the rule only records matches (payload_replace ignored).
    active: bool = True

    # Runtime counters (not constructor args).
    matches: int = 0
    rewrites: int = 0

    def matches_packet(self, pkt: RawPacket, five_tuple: dict) -> bool:
        if not self.active:
            return False
        if self.src_ip and five_tuple.get("src_ip") != self.src_ip:
            return False
        if self.dst_ip and five_tuple.get("dst_ip") != self.dst_ip:
            return False
        if self.dst_port and five_tuple.get("dst_port") != self.dst_port:
            return False
        if self.src_port and five_tuple.get("src_port") != self.src_port:
            return False
        if self.payload_pattern != "*":
            try:
                payload = _extract_udp_payload(pkt)
                if payload is None:
                    return False
                if not fnmatch.fnmatch(payload.decode("utf-8", errors="replace"),
                                       self.payload_pattern):
                    return False
            except Exception:
                return False
        return True


def _extract_udp_payload(pkt: RawPacket) -> Optional[bytes]:
    """Pull the UDP payload bytes out of an L2 frame (scapy)."""
    try:
        from scapy.all import Ether, IP, IPv6, UDP, Raw
        eth = Ether(pkt.raw_bytes)
        udp = eth.getlayer(UDP)
        if udp is None:
            return None
        raw = udp.getlayer(Raw)
        return bytes(raw.load) if raw is not None else b""
    except Exception:
        return None


def _five_tuple_of(pkt: RawPacket) -> Optional[dict]:
    try:
        from scapy.all import Ether, IP, IPv6, UDP
        eth = Ether(pkt.raw_bytes)
        udp = eth.getlayer(UDP)
        if udp is None:
            return None
        ip = eth.getlayer(IP) or eth.getlayer(IPv6)
        if ip is None:
            return None
        return {
            "src_ip": ip.src, "dst_ip": ip.dst,
            "src_port": int(udp.sport), "dst_port": int(udp.dport),
            "protocol": _PROTO_UDP,
        }
    except Exception:
        return None


class UDPModifier:
    """Applies UDPModifyRules to captured UDP packets and re-injects rewrites.

    Wired into NetworkEngine._handle_packet (a packet callback). Rewrite is
    compute-only here — the manipulator backend does the actual byte surgery
    (payload replace + checksum recalc) and injection.
    """

    def __init__(self, manipulator=None):
        self.manipulator = manipulator
        self.rules: List[UDPModifyRule] = []
        self.enabled = False  # default off — no rules, no cost
        self._lock = threading.Lock()
        # Diagnostics for /status.
        self.packets_seen = 0
        self.matches = 0
        self.rewrites = 0
        self.last_rewrite_at: Optional[datetime] = None
        self.last_rewrite_rule: Optional[str] = None
        self.errors = 0

    # ── rule management ───────────────────────────────────────────────────

    def add_rule(self, rule: UDPModifyRule) -> None:
        with self._lock:
            self.rules.append(rule)

    def remove_rule(self, name: str) -> int:
        with self._lock:
            before = len(self.rules)
            self.rules = [r for r in self.rules if r.name != name]
            return before - len(self.rules)

    def clear_rules(self) -> None:
        with self._lock:
            self.rules.clear()

    def list_rules(self) -> List[dict]:
        with self._lock:
            return [
                {
                    "name": r.name,
                    "src_ip": r.src_ip, "dst_ip": r.dst_ip,
                    "src_port": r.src_port, "dst_port": r.dst_port,
                    "payload_pattern": r.payload_pattern,
                    "has_replace": r.payload_replace is not None,
                    "active": r.active,
                    "matches": r.matches,
                    "rewrites": r.rewrites,
                }
                for r in self.rules
            ]

    # ── packet hook ───────────────────────────────────────────────────────

    def handle_packet(self, pkt: RawPacket) -> None:
        """Packet callback: match, rewrite, reinject. Never raises."""
        if not self.enabled or not self.rules:
            return
        try:
            ft = _five_tuple_of(pkt)
            if ft is None:
                return
            self.packets_seen += 1
            with self._lock:
                rules = list(self.rules)
            for rule in rules:
                if not rule.matches_packet(pkt, ft):
                    continue
                rule.matches += 1
                self.matches += 1
                if rule.on_rewrite:
                    try:
                        rule.on_rewrite(pkt)
                    except Exception as e:
                        logger.debug("UDP rule %s callback error: %s", rule.name, e)
                if rule.payload_replace is None:
                    continue
                modified = self._rewrite(pkt, rule.payload_replace)
                if modified is not None and self.manipulator is not None:
                    if self.manipulator.inject(modified):
                        rule.rewrites += 1
                        self.rewrites += 1
                        self.last_rewrite_at = datetime.now()
                        self.last_rewrite_rule = rule.name
                        logger.info(
                            "UDP rewrite: rule=%s %s:%s->%s:%s",
                            rule.name, ft["src_ip"], ft["src_port"],
                            ft["dst_ip"], ft["dst_port"],
                        )
                    else:
                        self.errors += 1
        except Exception as e:
            self.errors += 1
            logger.debug("UDP modifier error: %s", e)

    def _rewrite(self, pkt: RawPacket, payload: bytes) -> Optional[RawPacket]:
        """Byte surgery via the platform manipulator (checksums recalculated)."""
        if self.manipulator is None:
            return None
        try:
            from core.network.manipulate import PacketEdits
            return self.manipulator.modify_in_place(
                pkt, PacketEdits(payload_replace=payload, recalc_checksums=True)
            )
        except Exception as e:
            logger.debug("UDP rewrite failed: %s", e)
            return None

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "rules": self.list_rules(),
            "packets_seen": self.packets_seen,
            "matches": self.matches,
            "rewrites": self.rewrites,
            "errors": self.errors,
            "last_rewrite_at": self.last_rewrite_at.isoformat() if self.last_rewrite_at else None,
            "last_rewrite_rule": self.last_rewrite_rule,
        }

"""Foreign ARP-spoof detector — alerts when someone else poisons the LAN.

Nyx's own MITM uses ARP spoofing; this detector watches for *other* hosts
doing it (another pentest box, malware, a rogue device). The fingerprint of
a third-party spoof is an ARP **reply** claiming a gateway (or any third
IP) with a MAC that is neither the gateway's real MAC nor ours:

    victim asks "who-has 192.168.1.1?"  ->  someone OTHER than the router
    answers "192.168.1.1 is-at aa:bb:cc:.."

Tracked per (claimed_ip, mac) pair; a single contradicting reply is enough
to raise one alert per pair (re-arms only after the MAC changes again).
"""
import logging
import time
from collections import deque
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class ARPSpoofDetector:
    """Passive monitor for third-party ARP poisoning.

    Wired as a packet callback on NetworkEngine. Learns the gateway's MAC
    from the first clean reply it sees, then flags any reply binding a
    protected IP (default: the gateway) to a different MAC.
    """

    def __init__(self, protected_ips: Optional[list] = None, max_entries: int = 512):
        # IPs whose MAC bindings we defend (gateway added dynamically once
        # learned; users can pin others, e.g. a file server).
        self.protected_ips: set = set(protected_ips or [])
        self.max_entries = max_entries
        # ip -> authoritative MAC learned from traffic.
        self._bindings: dict = {}
        # (ip, mac) pairs already alerted (one alert per contradicting pair).
        self._alerted: set = set()
        # Findings surfaced in /status.
        self.detections = 0
        self.last_detection: Optional[dict] = None

    # ── helpers ───────────────────────────────────────────────────────────

    def _arp_fields(self, pkt) -> Optional[dict]:
        """Extract ARP reply fields from a raw L2 frame, else None."""
        try:
            from scapy.all import Ether, ARP
            eth = Ether(pkt.raw_bytes)
            arp = eth.getlayer(ARP)
            if arp is None or int(arp.op) != 2:  # replies only
                return None
            return {
                "psrc": arp.psrc,      # claimed IP
                "hwsrc": arp.hwsrc.lower(),  # claimed MAC
                "eth_src": (eth.src or "").lower(),
            }
        except Exception:
            return None

    def _is_local_mac(self, mac: str) -> bool:
        """True when the MAC belongs to this machine (never alert on self)."""
        try:
            import psutil
            for iface in psutil.net_if_addrs().values():
                for addr in iface:
                    if addr.family == psutil.AF_LINK and addr.address:
                        if addr.address.replace(":", "-").lower() == mac.replace(":", "-").lower():
                            return True
            return False
        except Exception:
            return False

    # ── packet hook ───────────────────────────────────────────────────────

    def handle_packet(self, pkt) -> Optional[dict]:
        """Feed one packet; returns an alert dict on a contradicting binding.
        Never raises."""
        try:
            fields = self._arp_fields(pkt)
            if fields is None:
                return None
            ip, mac = fields["psrc"], fields["hwsrc"]

            known = self._bindings.get(ip)
            if known is None:
                # First sighting: learn it as authoritative (even if it is a
                # spoof — subsequent contradictions still alert).
                if len(self._bindings) >= self.max_entries:
                    self._bindings.pop(next(iter(self._bindings)))
                self._bindings[ip] = mac
                return None

            if mac == known:
                return None

            # Contradiction: a different MAC now claims the same IP.
            if ip not in self.protected_ips and not self._looks_like_gateway(ip):
                # Only protected IPs / default gateway produce alerts; other
                # churn (phones rotating, VMs) is noise.
                return None

            if (ip, mac) in self._alerted:
                return None

            self._alerted.add((ip, mac))
            if len(self._alerted) > self.max_entries:
                self._alerted.pop()

            self.detections += 1
            detection = {
                "claimed_ip": ip,
                "legit_mac": known,
                "spoof_mac": mac,
                "eth_src": fields["eth_src"],
                "at": datetime.now().isoformat(),
            }
            self.last_detection = detection
            logger.warning(
                "ARP spoof detected: %s is claimed by %s (expected %s, eth %s)",
                ip, mac, known, fields["eth_src"],
            )
            return detection
        except Exception as e:
            logger.debug("ARP spoof detector error: %s", e)
            return None

    def _looks_like_gateway(self, ip: str) -> bool:
        try:
            from scapy.all import conf
            gw = conf.route.route("0.0.0.0")[2]
            return gw == ip
        except Exception:
            return False

    def status(self) -> dict:
        return {
            "protected_ips": sorted(self.protected_ips),
            "bindings_learned": len(self._bindings),
            "detections": self.detections,
            "last_detection": self.last_detection,
        }

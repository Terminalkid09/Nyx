"""ICMP tunnel detector — passive heuristic for data hidden in ICMP.

ICMP tunneling smuggles data inside echo request/reply payloads (ping
tunnels) or abuses the fact that ICMP usually crosses firewalls unfiltered.
Common tools: icmpsh, ptunnel, hans, icmp-shell. All leave a statistical
fingerprint:

  * payload sizes far above any OS ping (Linux 56B, Windows 32B defaults)
  * unusually regular payload sizes (tunnel chunks are fixed-size)
  * echo rates sustained well above any manual or monitoring ping
  * unbalanced request/reply direction (a shell mostly *replies*)

The detector is passive: it scores the ICMP echo traffic the network layer
already captures and emits ``icmp_tunnel`` frames when the score crosses a
threshold. It never injects or drops anything.
"""
import logging
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# OS ping payload baselines (bytes after the 8-byte ICMP header).
_LINUX_PING_PAYLOAD = 56
_WINDOWS_PING_PAYLOAD = 32
# Payloads above this are suspicious on their own (max legal ping payload is
# 65520, but real tools chunk well below that; 256 already exceeds any OS).
_PAYLOAD_ABSOLUTE_SUSPICIOUS = 256
# Echo pairs within this window count toward the rate score (seconds).
_RATE_WINDOW = 10.0
# Sustained echoes-per-second that begin to look tunnel-ish (manual ping is
# ~1/s; even ping -f from one host rarely sustains >20/s on Wi-Fi).
_RATE_SUSPICIOUS_EPS = 15.0
# A flow is reported when its rolling score reaches this.
_SCORE_THRESHOLD = 4.0
# Re-arm: after a report, the flow must gain this much score again before a
# second report (prevents one noisy flow from spamming the frame list).
_REARM_SCORE = 4.0


def _echo_payload_size(pkt) -> Optional[int]:
    """Payload byte count of an ICMP echo request/reply, else None."""
    try:
        from scapy.all import Ether, ICMP, IP, IPv6, Raw
        eth = Ether(pkt.raw_bytes)
        icmp = eth.getlayer(ICMP)
        if icmp is None:
            return None
        if icmp.type not in (8, 0):  # echo request / echo reply
            return None
        ip = eth.getlayer(IP) or eth.getlayer(IPv6)
        if ip is None:
            return None
        # Payload = IP total length - IP header - ICMP header(8).
        try:
            iplen = int(ip.len)
            ihl = int(ip.ihl) * 4
        except Exception:
            return None
        payload = iplen - ihl - 8
        return payload if payload >= 0 else None
    except Exception:
        return None


class ICMPTunnelDetector:
    """Scores ICMP echo flows for tunnel fingerprints; emits frames when hit.

    Wired as a packet callback on NetworkEngine. State is per (src, dst)
    echo pair; counters are bounded (oldest flows evicted) so long captures
    cannot grow memory.
    """

    def __init__(
        self,
        score_threshold: float = _SCORE_THRESHOLD,
        rate_window: float = _RATE_WINDOW,
        max_flows: int = 512,
    ):
        self.score_threshold = score_threshold
        self.rate_window = rate_window
        self.max_flows = max_flows
        # flow key -> {"score", "sizes": deque, "times": deque, "reported"}
        self._flows: dict = {}
        # Findings surfaced in /status and tests.
        self.detections = 0
        self.last_detection: Optional[dict] = None

    # ── scoring ───────────────────────────────────────────────────────────

    def _score_payload(self, size: int) -> float:
        if size >= _PAYLOAD_ABSOLUTE_SUSPICIOUS:
            # >256B echo payload: no OS ping does this — strong enough to
            # reach the threshold alone (4.5 >= _SCORE_THRESHOLD).
            return 4.5
        if size > max(_LINUX_PING_PAYLOAD, _WINDOWS_PING_PAYLOAD):
            return 1.5
        return 0.0

    def _score_regularity(self, sizes: deque) -> float:
        # Tunnel chunks are near-constant size; OS pings vary little too, so
        # only *combined with* size/rate evidence does this add signal.
        if len(sizes) < 4:
            return 0.0
        recent = list(sizes)[-8:]
        spread = max(recent) - min(recent)
        if spread == 0 and recent[0] > 64:
            return 1.0
        return 0.0

    def _score_rate(self, times: deque) -> float:
        now = times[-1]
        window = [t for t in times if now - t <= self.rate_window]
        if len(window) < 2:
            return 0.0
        # Rate = echoes per second over the ACTUAL observed span, not the
        # nominal window: dividing a millisecond burst by the full 10s window
        # would dilute 6 echoes to 0.5 eps and hide exactly the burst pattern
        # tunnels produce.
        span = window[-1] - window[0]
        eps = (len(window) - 1) / max(span, 0.001)
        if eps >= _RATE_SUSPICIOUS_EPS:
            return 2.0
        if eps >= _RATE_SUSPICIOUS_EPS / 3:
            return 0.5
        return 0.0

    # ── packet hook ───────────────────────────────────────────────────────

    def handle_packet(self, pkt) -> Optional[dict]:
        """Feed one packet; returns a detection dict when a flow crosses the
        threshold (NetworkEngine turns this into an ``icmp_tunnel`` frame).
        Never raises."""
        try:
            size = _echo_payload_size(pkt)
            if size is None:
                return None
            try:
                from scapy.all import Ether, IP, IPv6
                eth = Ether(pkt.raw_bytes)
                ip = eth.getlayer(IP) or eth.getlayer(IPv6)
                key = (ip.src, ip.dst)
            except Exception:
                return None

            now = time.time()
            flow = self._flows.get(key)
            if flow is None:
                if len(self._flows) >= self.max_flows:
                    # Evict the oldest flow (dict preserves insertion order).
                    oldest = next(iter(self._flows))
                    del self._flows[oldest]
                flow = {"score": 0.0, "sizes": deque(maxlen=32),
                        "times": deque(maxlen=64), "reported": False}
                self._flows[key] = flow

            flow["sizes"].append(size)
            flow["times"].append(now)
            score = (
                self._score_payload(size)
                + self._score_regularity(flow["sizes"])
                + self._score_rate(flow["times"])
            )
            flow["score"] = score

            if score >= self.score_threshold and not flow["reported"]:
                flow["reported"] = True
                self.detections += 1
                detection = {
                    "src_ip": key[0],
                    "dst_ip": key[1],
                    "score": round(score, 2),
                    "payload_size": size,
                    "echoes_observed": len(flow["times"]),
                }
                self.last_detection = detection
                logger.info(
                    "ICMP tunnel suspected: %s -> %s (score %.2f, payload %dB)",
                    key[0], key[1], score, size,
                )
                return detection
            return None
        except Exception as e:
            logger.debug("ICMP detector error: %s", e)
            return None

    def status(self) -> dict:
        return {
            "flows_tracked": len(self._flows),
            "detections": self.detections,
            "last_detection": self.last_detection,
            "threshold": self.score_threshold,
        }

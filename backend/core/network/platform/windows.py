"""Windows packet manipulation backend (WinDivert)."""

import logging
from typing import Optional

from core.network.capture import RawPacket
from core.network.manipulate import PacketManipulatorBackend

logger = logging.getLogger(__name__)


class WindowsManipulatorBackend(PacketManipulatorBackend):
    """Windows packet injection/modification using WinDivert.

    Passive capture on Windows uses the same scapy AsyncSniffer as every
    other platform (Npcap) — see core.network.capture.
    """

    def __init__(self, interface: str):
        self.interface = interface
        self._windivert_handle = None

    def inject(self, pkt: RawPacket) -> bool:
        try:
            import pydivert
            if self._windivert_handle is None:
                self._windivert_handle = pydivert.WinDivert(
                    "true",
                    layer=pydivert.Layer.NETWORK
                )
                self._windivert_handle.open()
            self._windivert_handle.send(pkt.raw_bytes)
            return True
        except Exception as e:
            logger.error("WinDivert inject error: %s", e)
            return False

    def modify_in_place(self, pkt: RawPacket, edits: "PacketEdits") -> RawPacket:
        try:
            from scapy.all import Ether, IP, TCP, UDP, Raw
            raw = pkt.raw_bytes
            # Captured packets are L2 (Ethernet) frames — parsing the raw
            # bytes as a bare IP() datagram (old code) either raised or
            # misparsed the MAC header, so modification silently no-oped.
            eth = Ether(raw)
            ip = eth.getlayer(IP)
            container = eth
            if ip is None:
                # Bare IP datagram (no L2 header) — injected/synthetic.
                if not raw or raw[0] >> 4 != 4:
                    return pkt
                ip = IP(raw)
                container = ip

            if edits.payload_replace and Raw in ip:
                ip[Raw].load = edits.payload_replace

            if edits.tcp_seq_delta and TCP in ip:
                ip[TCP].seq += edits.tcp_seq_delta

            if edits.tcp_ack_set and TCP in ip:
                ip[TCP].ack = edits.tcp_ack_set

            if edits.recalc_checksums:
                if IP in ip:
                    del ip[IP].chksum
                if TCP in ip:
                    del ip[TCP].chksum
                if UDP in ip:
                    del ip[UDP].chksum

            return RawPacket(
                timestamp=pkt.timestamp,
                raw_bytes=bytes(container),
                interface=pkt.interface,
                metadata=pkt.metadata
            )
        except Exception as e:
            logger.error("Packet modify error: %s", e)
            return pkt

    def drop(self, pkt_id: int) -> bool:
        return False

    def close(self):
        if self._windivert_handle:
            try:
                self._windivert_handle.close()
            except Exception:
                pass
            self._windivert_handle = None

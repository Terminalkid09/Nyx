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
            from scapy.all import IP, TCP, UDP, Raw
            scapy_pkt = IP(pkt.raw_bytes)

            if edits.payload_replace and Raw in scapy_pkt:
                scapy_pkt[Raw].load = edits.payload_replace

            if edits.tcp_seq_delta and TCP in scapy_pkt:
                scapy_pkt[TCP].seq += edits.tcp_seq_delta

            if edits.tcp_ack_set and TCP in scapy_pkt:
                scapy_pkt[TCP].ack = edits.tcp_ack_set

            if edits.recalc_checksums:
                if IP in scapy_pkt:
                    del scapy_pkt[IP].chksum
                if TCP in scapy_pkt:
                    del scapy_pkt[TCP].chksum
                if UDP in scapy_pkt:
                    del scapy_pkt[UDP].chksum

            return RawPacket(
                timestamp=pkt.timestamp,
                raw_bytes=bytes(scapy_pkt),
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

"""Linux packet manipulation backend (raw socket injection)."""

import logging
import socket
from typing import Optional

from core.network.capture import RawPacket
from core.network.manipulate import PacketManipulatorBackend

logger = logging.getLogger(__name__)


class LinuxManipulatorBackend(PacketManipulatorBackend):
    """Linux packet injection using AF_PACKET raw sockets.

    Passive capture on Linux uses the same scapy AsyncSniffer as every other
    platform (see core.network.capture) — no AF_PACKET sniffing loop needed.
    Injection still requires a raw socket (root), and in-path drop/modify is
    only possible via netfilterqueue + iptables NFQUEUE (optional).
    """

    def __init__(self, interface: str):
        self.interface = interface
        self._inject_sock: Optional[socket.socket] = None
        self._nfqueue = None

    def _get_inject_socket(self) -> socket.socket:
        if self._inject_sock is None:
            self._inject_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self._inject_sock.bind((self.interface, 0))
        return self._inject_sock

    def inject(self, pkt: RawPacket) -> bool:
        try:
            sock = self._get_inject_socket()
            sock.send(pkt.raw_bytes)
            return True
        except Exception as e:
            logger.error("Raw socket inject error: %s", e)
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

    def setup_nfqueue(self, queue_num: int = 1) -> bool:
        try:
            import netfilterqueue
            self._nfqueue = netfilterqueue.NetfilterQueue()
            self._nfqueue.bind(queue_num, self._nfqueue_callback)
            return True
        except Exception as e:
            logger.warning("netfilterqueue not available: %s", e)
            return False

    def _nfqueue_callback(self, pkt):
        pkt.accept()

    def close(self):
        if self._inject_sock:
            self._inject_sock.close()
            self._inject_sock = None
        if self._nfqueue:
            try:
                self._nfqueue.unbind()
            except Exception:
                pass
            self._nfqueue = None

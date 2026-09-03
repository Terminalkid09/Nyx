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

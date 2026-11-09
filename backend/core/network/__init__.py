"""Network Layer for Nyx.

Provides cross-platform network utilities for:
- Packet capture (scapy AsyncSniffer — works on Windows/Linux/macOS)
- Packet injection/modification (platform backends)
- TCP/UDP stream reconstruction
- Protocol decoding (scapy adapters for DNS/DHCP/ARP/ICMP, QUIC)
- PCAP/PCAPNG I/O
- Live statistics
"""

from core.network.capture import PacketCapture, RawPacket, CaptureStats
from core.network.manipulate import PacketManipulator, PacketEdits, PacketManipulatorBackend
from core.network.reassemble import TCPReassembler, UDPFlowTracker, TCPStream, UDPFlow, TCPFrame
from core.network.protocols import (
    ProtocolDecoder,
    ProtocolFrame,
    FiveTuple,
    DNSDecoder,
    DHCPDecoder,
    ARPDecoder,
    ICMPDecoder,
    QUICDecoder,
    load_all_decoders,
    register_decoder,
)
from core.network.pcap import PCAPWriter, PCAPReader, PCAPNGWriter
from core.network.stats import NetworkStats, StatsCollector, LiveStatsBroadcaster
from core.network.platform import create_manipulator_backend

__all__ = [
    "PacketCapture",
    "RawPacket",
    "CaptureStats",
    "PacketManipulator",
    "PacketEdits",
    "PacketManipulatorBackend",
    "TCPReassembler",
    "UDPFlowTracker",
    "TCPStream",
    "UDPFlow",
    "TCPFrame",
    "ProtocolDecoder",
    "ProtocolFrame",
    "FiveTuple",
    "DNSDecoder",
    "DHCPDecoder",
    "ARPDecoder",
    "ICMPDecoder",
    "QUICDecoder",
    "load_all_decoders",
    "register_decoder",
    "PCAPWriter",
    "PCAPReader",
    "PCAPNGWriter",
    "NetworkStats",
    "StatsCollector",
    "LiveStatsBroadcaster",
    "create_manipulator_backend",
]

"""Protocol decoders package - pluggable protocol decoders."""

from core.network.protocols.base import ProtocolDecoder, ProtocolFrame, FiveTuple
from core.network.protocols.scapy_adapters import (
    DNSDecoder,
    DHCPDecoder,
    ARPDecoder,
    ICMPDecoder,
)
from core.network.protocols.quic import QUICDecoder

_DECODERS: list[type[ProtocolDecoder]] = [
    DNSDecoder,
    DHCPDecoder,
    ARPDecoder,
    ICMPDecoder,
    QUICDecoder,
]


def load_all_decoders() -> list[ProtocolDecoder]:
    """Instantiate all registered protocol decoders."""
    return [d() for d in _DECODERS]


def register_decoder(decoder_cls: type[ProtocolDecoder]) -> None:
    """Register a custom protocol decoder."""
    if decoder_cls not in _DECODERS:
        _DECODERS.append(decoder_cls)


__all__ = [
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
]

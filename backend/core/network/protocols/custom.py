"""Custom protocol decoder plugin interface."""
import logging
from abc import ABC
from datetime import datetime
from typing import Iterator, Optional, Callable

from core.network.protocols.base import ProtocolDecoder, ProtocolFrame, TCPStream, UDPFlow

logger = logging.getLogger(__name__)


class CustomProtocolDecoder(ProtocolDecoder):
    """Base class for custom protocol decoders - extend for proprietary protocols."""

    name = "custom"
    ports = set()

    def __init__(self, name: str = "custom", ports: set = None, match_func: Callable = None):
        self._name = name
        self._ports = ports or set()
        self._match_func = match_func

    @property
    def name(self) -> str:
        return self._name

    @property
    def ports(self) -> set:
        return self._ports

    def can_decode(self, stream: TCPStream | UDPFlow) -> bool:
        if self._match_func:
            return self._match_func(stream)
        if self._ports:
            if isinstance(stream, TCPStream):
                return stream.five_tuple.dst_port in self._ports or stream.five_tuple.src_port in self._ports
            if isinstance(stream, UDPFlow):
                return stream.five_tuple.dst_port in self._ports or stream.five_tuple.src_port in self._ports
        return False

    def decode(self, stream: TCPStream | UDPFlow) -> Iterator[ProtocolFrame]:
        if isinstance(stream, TCPStream):
            for frame in stream.frames:
                if frame.payload:
                    yield ProtocolFrame(
                        frame_type=f"{self._name}_tcp",
                        timestamp=frame.timestamp,
                        data={"length": len(frame.payload)},
                        raw_ref=frame.payload,
                        five_tuple=stream.five_tuple
                    )
        else:
            for pkt in stream.packets:
                if pkt.payload:
                    yield ProtocolFrame(
                        frame_type=f"{self._name}_udp",
                        timestamp=pkt.timestamp,
                        data={"length": len(pkt.payload)},
                        raw_ref=pkt.payload,
                        five_tuple=stream.five_tuple
                    )


def create_custom_decoder(
    name: str,
    ports: set[int],
    match_func: Optional[Callable] = None,
    decode_func: Optional[Callable] = None
) -> type[CustomProtocolDecoder]:
    """Factory to create custom decoder classes dynamically."""

    class DynamicDecoder(CustomProtocolDecoder):
        def __init__(self):
            super().__init__(name, ports, match_func)
            self._decode_func = decode_func

        def decode(self, stream: TCPStream | UDPFlow) -> Iterator[ProtocolFrame]:
            if self._decode_func:
                yield from self._decode_func(stream)
            else:
                yield from super().decode(stream)

    return DynamicDecoder
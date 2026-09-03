"""Packet injection/modification interface."""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from core.network.capture import RawPacket

logger = logging.getLogger(__name__)


@dataclass
class PacketEdits:
    """Declarative packet modifications."""
    payload_replace: Optional[bytes] = None
    tcp_seq_delta: int = 0
    tcp_ack_set: Optional[int] = None
    recalc_checksums: bool = True


class PacketManipulatorBackend(ABC):
    """Abstract base for platform-specific packet manipulation backends."""

    @abstractmethod
    def inject(self, pkt: RawPacket) -> bool:
        pass

    @abstractmethod
    def modify_in_place(self, pkt: RawPacket, edits: PacketEdits) -> RawPacket:
        pass

    @abstractmethod
    def drop(self, pkt_id: int) -> bool:
        pass

    @abstractmethod
    def close(self) -> None:
        pass


class PacketManipulator:
    """Unified packet injection/modification interface."""

    def __init__(self, interface: str):
        self.interface = interface
        self._backend: Optional[PacketManipulatorBackend] = None

    def start(self) -> None:
        if self._backend:
            return
        from core.network.platform import create_manipulator_backend
        self._backend = create_manipulator_backend(self.interface)
        logger.info("Packet manipulator started on %s", self.interface)

    def stop(self) -> None:
        if self._backend:
            self._backend.close()
            self._backend = None
        logger.info("Packet manipulator stopped")

    def inject(self, pkt: RawPacket) -> bool:
        if not self._backend:
            return False
        return self._backend.inject(pkt)

    def modify_in_place(self, pkt: RawPacket, edits: PacketEdits) -> RawPacket:
        if not self._backend:
            return pkt
        return self._backend.modify_in_place(pkt, edits)

    def drop(self, pkt_id: int) -> bool:
        if not self._backend:
            return False
        return self._backend.drop(pkt_id)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
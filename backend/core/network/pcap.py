"""PCAP/PCAPNG writer and reader - pure Python."""
import logging
import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from core.network.capture import RawPacket

logger = logging.getLogger(__name__)

DLT_EN10MB = 1
PCAP_MAGIC = 0xa1b2c3d4
PCAP_SWAPPED_MAGIC = 0xd4c3b2a1
PCAPNG_MAGIC = 0x0A0D0D0A
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D


@dataclass
class PCAPGlobalHeader:
    magic_number: int = PCAP_MAGIC
    version_major: int = 2
    version_minor: int = 4
    thiszone: int = 0
    sigfigs: int = 0
    snaplen: int = 65535
    network: int = DLT_EN10MB

    def pack(self) -> bytes:
        return struct.pack(
            "<IHHIIII",
            self.magic_number,
            self.version_major,
            self.version_minor,
            self.thiszone,
            self.sigfigs,
            self.snaplen,
            self.network
        )


class PCAPWriter:
    """PCAP file writer."""

    def __init__(self, path: str, linktype: int = DLT_EN10MB, snaplen: int = 65535):
        self.path = Path(path)
        self.linktype = linktype
        self.snaplen = snaplen
        self._fh = None
        self._packet_count = 0

    def open(self) -> None:
        self._fh = open(self.path, "wb")
        header = PCAPGlobalHeader(network=self.linktype, snaplen=self.snaplen)
        self._fh.write(header.pack())
        self._packet_count = 0

    def write_packet(self, pkt: RawPacket) -> None:
        if not self._fh:
            self.open()

        ts_sec = int(pkt.timestamp.timestamp())
        ts_usec = int((pkt.timestamp.timestamp() - ts_sec) * 1_000_000)
        pkt_len = min(len(pkt.raw_bytes), self.snaplen)

        pkt_header = struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)
        self._fh.write(pkt_header)
        self._fh.write(pkt.raw_bytes[:pkt_len])
        self._packet_count += 1

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
            logger.info("PCAP written: %s (%d packets)", self.path, self._packet_count)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        # Safety net: write_packet() auto-opens the file, so a caller that
        # forgets close() (or dies mid-flight) must not leak the descriptor.
        try:
            self.close()
        except Exception:
            pass


class PCAPReader:
    """PCAP file reader."""

    def __init__(self, path: str):
        self.path = Path(path)
        self._fh = None
        self._global_header = None

    def open(self) -> None:
        self._fh = open(self.path, "rb")
        header_data = self._fh.read(24)
        if len(header_data) < 24:
            raise ValueError("Invalid PCAP file")

        magic = struct.unpack("<I", header_data[:4])[0]
        if magic == PCAP_MAGIC:
            self._endian = "<"
        elif magic == PCAP_SWAPPED_MAGIC:
            self._endian = ">"
        else:
            raise ValueError(f"Not a PCAP file (magic {magic:#x})")

        self._global_header = struct.unpack(self._endian + "IHHIIII", header_data)

    def packets(self) -> Iterator[RawPacket]:
        if not self._fh:
            self.open()

        endian = self._endian
        while True:
            pkt_header = self._fh.read(16)
            if len(pkt_header) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", pkt_header)
            pkt_data = self._fh.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            timestamp = datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000)
            yield RawPacket(
                timestamp=timestamp,
                raw_bytes=pkt_data,
                interface="",
                metadata={"orig_len": orig_len}
            )

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class PCAPNGWriter:
    """PCAPNG file writer (big-endian, standard byte order)."""

    def __init__(self, path: str, linktype: int = DLT_EN10MB, snaplen: int = 65535):
        self.path = Path(path)
        self.linktype = linktype
        self.snaplen = snaplen
        self._fh = None
        self._packet_count = 0

    def open(self) -> None:
        self._fh = open(self.path, "wb")
        # Section Header Block (28 bytes, big-endian):
        #   type | total_len | byte-order magic | major | minor | section_length | total_len
        shb = struct.pack(">IIIHHqI", PCAPNG_MAGIC, 28, PCAPNG_BYTE_ORDER_MAGIC, 1, 0, -1, 28)
        self._fh.write(shb)
        # Interface Description Block (20 bytes):
        #   type | total_len | linktype | reserved | snaplen | total_len
        idb = struct.pack(">IIHHII", 1, 20, self.linktype, 0, self.snaplen, 20)
        self._fh.write(idb)
        self._packet_count = 0

    def write_packet(self, pkt: RawPacket) -> None:
        if not self._fh:
            self.open()

        # PCAPNG timestamp: 64-bit count of the interface's timestamp
        # resolution units since the epoch. The IDB declares no if_tsresol
        # option, so the default resolution is 10^-6 s (microseconds) and
        # the full value is microseconds-since-epoch — NOT sec<<32 | 2^-32
        # fraction (which Wireshark would read as seconds + millions of
        # seconds of fraction). Integer math avoids float drift on the
        # seconds*1e6 product.
        ts_sec = int(pkt.timestamp.timestamp())
        ts_usec = int(round((pkt.timestamp.timestamp() - ts_sec) * 1_000_000))
        micros = ts_sec * 1_000_000 + ts_usec
        ts_high = (micros >> 32) & 0xFFFFFFFF
        ts_low = micros & 0xFFFFFFFF
        pkt_len = len(pkt.raw_bytes)

        padding = (4 - (pkt_len % 4)) % 4
        # Fixed fields (28) + data + padding + trailing length field (4).
        total_len = 32 + pkt_len + padding

        epb = struct.pack(
            ">IIIIIII",
            6,            # Enhanced Packet Block
            total_len,
            0,            # interface_id
            ts_high,
            ts_low,
            pkt_len,      # captured length
            pkt_len       # original length
        )
        self._fh.write(epb)
        self._fh.write(pkt.raw_bytes)
        self._fh.write(b"\x00" * padding)
        self._fh.write(struct.pack(">I", total_len))
        self._packet_count += 1

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
            logger.info("PCAPNG written: %s (%d packets)", self.path, self._packet_count)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
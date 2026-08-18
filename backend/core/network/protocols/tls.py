"""TLS Record Layer decoder."""
import logging
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional

from core.network.protocols.base import ProtocolDecoder, ProtocolFrame, TCPStream, UDPFlow, FiveTuple

logger = logging.getLogger(__name__)


class TLSContentType:
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    HEARTBEAT = 24


class TLSHandshakeType:
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    CERTIFICATE_URL = 21
    CERTIFICATE_STATUS = 22
    KEY_UPDATE = 24
    MESSAGE_HASH = 254


@dataclass
class TLSRecord:
    content_type: int
    version: int
    length: int
    payload: bytes


@dataclass
class TLSHandshake:
    msg_type: int
    length: int
    payload: bytes


class TLSDecoder(ProtocolDecoder):
    """TLS Record Layer decoder - extracts SNI and handshake info."""

    name = "tls"
    ports = {443, 8443, 9443, 993, 995, 5223, 8883}

    def can_decode(self, stream: TCPStream | UDPFlow) -> bool:
        if not isinstance(stream, TCPStream):
            return False
        if not stream.frames:
            return False
        first_frame = stream.frames[0]
        return len(first_frame.payload) >= 5 and first_frame.payload[0] in (
            TLSContentType.HANDSHAKE, TLSContentType.APPLICATION_DATA)

    def decode(self, stream: TCPStream) -> Iterator[ProtocolFrame]:
        for frame in stream.frames:
            if not frame.payload:
                continue

            offset = 0
            while offset < len(frame.payload):
                record = self._parse_record(frame.payload[offset:])
                if not record:
                    break

                yield ProtocolFrame(
                    frame_type="tls_record",
                    timestamp=frame.timestamp,
                    data={
                        "content_type": record.content_type,
                        "version": record.version,
                        "length": record.length,
                    },
                    raw_ref=record.payload,
                    five_tuple=stream.five_tuple
                )

                if record.content_type == TLSContentType.HANDSHAKE:
                    handshake_frames = self._parse_handshake(record.payload, frame.timestamp, stream.five_tuple)
                    for hf in handshake_frames:
                        yield hf

                offset += 5 + record.length

    def _parse_record(self, data: bytes) -> Optional[TLSRecord]:
        if len(data) < 5:
            return None
        try:
            content_type, version, length = struct.unpack(">BHH", data[:5])
            if len(data) < 5 + length:
                return None
            return TLSRecord(content_type, version, length, data[5:5+length])
        except Exception:
            return None

    def _parse_handshake(self, data: bytes, timestamp: datetime, five_tuple: FiveTuple) -> list[ProtocolFrame]:
        frames = []
        offset = 0
        while offset < len(data):
            if offset + 4 > len(data):
                break
            try:
                msg_type, length = struct.unpack(">B3s", data[offset:offset+4])
                length = int.from_bytes(length, "big")
                if offset + 4 + length > len(data):
                    break
                payload = data[offset+4:offset+4+length]

                if msg_type == TLSHandshakeType.CLIENT_HELLO:
                    sni = self._extract_sni(payload)
                    frames.append(ProtocolFrame(
                        frame_type="tls_client_hello",
                        timestamp=timestamp,
                        data={"sni": sni, "raw_length": len(payload)},
                        raw_ref=payload,
                        five_tuple=five_tuple
                    ))
                elif msg_type == TLSHandshakeType.SERVER_HELLO:
                    frames.append(ProtocolFrame(
                        frame_type="tls_server_hello",
                        timestamp=timestamp,
                        data={"raw_length": len(payload)},
                        raw_ref=payload,
                        five_tuple=five_tuple
                    ))

                offset += 4 + length
            except Exception:
                break
        return frames

    def _extract_sni(self, client_hello: bytes) -> Optional[str]:
        try:
            offset = 0
            if len(client_hello) < 34:
                return None
            offset = 34

            session_id_len = client_hello[offset]
            offset += 1 + session_id_len

            if offset + 2 > len(client_hello):
                return None
            cipher_suites_len = int.from_bytes(client_hello[offset:offset+2], "big")
            offset += 2 + cipher_suites_len

            if offset >= len(client_hello):
                return None
            compression_methods_len = client_hello[offset]
            offset += 1 + compression_methods_len

            if offset + 2 > len(client_hello):
                return None
            extensions_len = int.from_bytes(client_hello[offset:offset+2], "big")
            offset += 2
            extensions_end = offset + extensions_len

            while offset + 4 <= extensions_end and offset < len(client_hello):
                ext_type, ext_len = struct.unpack(">HH", client_hello[offset:offset+4])
                offset += 4
                if ext_type == 0:
                    if offset + 2 > len(client_hello):
                        break
                    sni_list_len = int.from_bytes(client_hello[offset:offset+2], "big")
                    offset += 2
                    while offset + 3 <= len(client_hello):
                        sni_type = client_hello[offset]
                        if sni_type == 0:
                            sni_len = int.from_bytes(client_hello[offset+1:offset+3], "big")
                            offset += 3
                            if offset + sni_len <= len(client_hello):
                                return client_hello[offset:offset+sni_len].decode("utf-8", errors="replace")
                        offset += 1
                    break
                else:
                    offset += ext_len
        except Exception:
            pass
        return None
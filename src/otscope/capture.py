from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .models import TransportPacket

MAX_BLOCK_BYTES = 32 * 1024 * 1024


@dataclass
class RawPacket:
    timestamp: float
    linktype: int
    data: bytes
    wire_len: int
    frame_number: int = 0
    interface_id: str = "0:0"
    decode_issue: str | None = None


class CaptureError(ValueError):
    pass


def read_capture(path: str | Path) -> Iterator[RawPacket]:
    path = Path(path)
    with path.open("rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        packets = _read_pcapng(fh) if magic == b"\x0a\x0d\x0d\x0a" else _read_pcap(fh)
        for number, packet in enumerate(packets, 1):
            packet.frame_number = number
            yield packet


def _read_pcap(fh) -> Iterator[RawPacket]:
    header = fh.read(24)
    if len(header) != 24:
        raise CaptureError("Not a valid PCAP file: global header is incomplete")

    magic = header[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats:
        raise CaptureError("Unsupported capture format or PCAP byte order")
    endian, resolution = formats[magic]
    linktype = struct.unpack(endian + "I", header[20:24])[0]

    while True:
        ph = fh.read(16)
        if not ph:
            return
        if len(ph) != 16:
            raise CaptureError("Truncated PCAP packet header")
        ts_sec, ts_frac, caplen, wirelen = struct.unpack(endian + "IIII", ph)
        if caplen > MAX_BLOCK_BYTES or caplen > wirelen:
            raise CaptureError("Invalid or unsupported PCAP packet length")
        data = fh.read(caplen)
        if len(data) != caplen:
            raise CaptureError("Truncated PCAP packet data")
        yield RawPacket(ts_sec + ts_frac / resolution, linktype, data, wirelen)


def _parse_options(data: bytes, endian: str) -> dict[int, list[bytes]]:
    out: dict[int, list[bytes]] = {}
    pos = 0
    while pos + 4 <= len(data):
        code, length = struct.unpack(endian + "HH", data[pos:pos + 4])
        pos += 4
        if code == 0:
            break
        if pos + length > len(data):
            raise CaptureError("Truncated PCAPNG option")
        value = data[pos:pos + length]
        out.setdefault(code, []).append(value)
        pos += (length + 3) & ~3
    return out


def _read_pcapng(fh) -> Iterator[RawPacket]:
    interfaces: list[tuple[int, float, int]] = []  # linktype, divisor, time offset
    endian = "<"
    section = -1

    while True:
        block_header = fh.read(8)
        if not block_header:
            return
        if len(block_header) != 8:
            raise CaptureError("Truncated PCAPNG block header")

        raw_type = block_header[:4]
        if raw_type == b"\x0a\x0d\x0d\x0a":
            # Need the BOM before endianness/length can be trusted.
            rest = fh.read(20)
            if len(rest) != 20:
                raise CaptureError("Truncated PCAPNG section header")
            bom = rest[0:4]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureError("Invalid PCAPNG byte-order magic")
            total_len = struct.unpack(endian + "I", block_header[4:8])[0]
            if total_len < 28 or total_len > MAX_BLOCK_BYTES or total_len % 4:
                raise CaptureError("Invalid PCAPNG section length")
            if total_len > 28:
                extra = fh.read(total_len - 28)
                if len(extra) != total_len - 28:
                    raise CaptureError("Truncated PCAPNG section header")
                trailer = extra[-4:]
            else:
                trailer = rest[-4:]
            if struct.unpack(endian + "I", trailer)[0] != total_len:
                raise CaptureError("Mismatched PCAPNG section length")
            interfaces = []
            section += 1
            continue

        block_type, total_len = struct.unpack(endian + "II", block_header)
        if total_len < 12 or total_len > MAX_BLOCK_BYTES or total_len % 4:
            raise CaptureError("Invalid PCAPNG block length")
        body_len = total_len - 12
        body = fh.read(body_len)
        trailer = fh.read(4)
        if len(body) != body_len or len(trailer) != 4:
            raise CaptureError("Truncated PCAPNG block")
        if struct.unpack(endian + "I", trailer)[0] != total_len:
            raise CaptureError("Mismatched PCAPNG block length")

        if block_type == 1:  # Interface Description Block
            if len(body) < 8:
                raise CaptureError("Incomplete PCAPNG interface description")
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            divisor = 1_000_000.0
            options = _parse_options(body[8:], endian)
            if 9 in options and options[9] and options[9][0]:
                val = options[9][0][0]
                if val & 0x80:
                    divisor = float(2 ** (val & 0x7F))
                else:
                    divisor = float(10 ** val)
            offset = 0
            if 14 in options and options[14] and len(options[14][0]) == 8:
                offset = struct.unpack(endian + "q", options[14][0])[0]
            interfaces.append((linktype, divisor, offset))

        elif block_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                raise CaptureError("Incomplete PCAPNG enhanced packet header")
            interface_id, ts_hi, ts_lo, caplen, wirelen = struct.unpack(endian + "IIIII", body[:20])
            if interface_id >= len(interfaces):
                raise CaptureError("PCAPNG packet references an unknown interface")
            if caplen > len(body)-20 or caplen > wirelen:
                raise CaptureError("Truncated PCAPNG enhanced packet data")
            linktype, divisor, offset = interfaces[interface_id]
            packet_data = body[20:20 + caplen]
            timestamp = ((ts_hi << 32) | ts_lo) / divisor + offset
            yield RawPacket(timestamp, linktype, packet_data, wirelen,
                            interface_id=f"{section}:{interface_id}")
        elif block_type in (2, 3):
            raise CaptureError("PCAPNG obsolete/simple packet blocks are not supported; convert the capture to enhanced packet blocks or PCAP")


def decode_transport(packet: RawPacket) -> TransportPacket | None:
    data = packet.data
    linktype = packet.linktype
    packet.decode_issue = "non_tcp_udp_or_unsupported"

    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        offset = 14
        ethertype = struct.unpack("!H", data[12:14])[0]
        while ethertype in (0x8100, 0x88A8, 0x9100):
            if len(data) < offset + 4:
                return None
            ethertype = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4
        if ethertype == 0x0800:
            return _decode_ipv4(data[offset:], packet)
        if ethertype == 0x86DD:
            return _decode_ipv6(data[offset:], packet)
        return None

    if linktype == 113:  # Linux cooked capture v1
        if len(data) < 16:
            return None
        proto = struct.unpack("!H", data[14:16])[0]
        if proto == 0x0800:
            return _decode_ipv4(data[16:], packet)
        if proto == 0x86DD:
            return _decode_ipv6(data[16:], packet)
    return None


def _decode_ipv4(data: bytes, raw: RawPacket) -> TransportPacket | None:
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    frag = struct.unpack("!H", data[6:8])[0]
    if frag & 0x3FFF:  # Any fragmentation; never decode a partial IP datagram.
        raw.decode_issue = "fragmented_ip"
        return None
    proto = data[9]
    src = str(ipaddress.IPv4Address(data[12:16]))
    dst = str(ipaddress.IPv4Address(data[16:20]))
    total_len = struct.unpack("!H", data[2:4])[0]
    if total_len < ihl:
        raw.decode_issue = "malformed_ip"
        return None
    payload = data[ihl:total_len]
    return _decode_l4(raw, src, dst, proto, payload)


def _decode_ipv6(data: bytes, raw: RawPacket) -> TransportPacket | None:
    if len(data) < 40 or data[0] >> 4 != 6:
        return None
    next_header = data[6]
    src = str(ipaddress.IPv6Address(data[8:24]))
    dst = str(ipaddress.IPv6Address(data[24:40]))
    payload_length = struct.unpack("!H", data[4:6])[0]
    if not payload_length:
        raw.decode_issue = "unsupported_ipv6_jumbogram"
        return None
    payload = data[40:40+payload_length]
    # Minimal support for common extension headers.
    while next_header in (0, 43, 60):
        if len(payload) < 8:
            return None
        nh = payload[0]
        ext_len = (payload[1] + 1) * 8
        payload = payload[ext_len:]
        next_header = nh
    if next_header == 44:  # fragment header
        if len(payload) < 8:
            return None
        fragment = struct.unpack("!H", payload[2:4])[0]
        if fragment & 0xFFF9:
            raw.decode_issue = "fragmented_ip"
            return None
        next_header = payload[0]
        payload = payload[8:]
    return _decode_l4(raw, src, dst, next_header, payload)


def _decode_l4(raw: RawPacket, src: str, dst: str, proto: int, data: bytes) -> TransportPacket | None:
    if proto == 6 and len(data) >= 20:
        sport, dport = struct.unpack("!HH", data[:4])
        offset = (data[12] >> 4) * 4
        if offset < 20 or len(data) < offset:
            return None
        flags = data[13]
        sequence = struct.unpack("!I", data[4:8])[0]
        raw.decode_issue = None
        return TransportPacket(raw.timestamp, src, dst, "tcp", sport, dport, data[offset:], raw.wire_len, flags,
                               sequence, raw.frame_number, raw.interface_id)
    if proto == 17 and len(data) >= 8:
        sport, dport = struct.unpack("!HH", data[:4])
        length = struct.unpack("!H", data[4:6])[0]
        if length < 8:
            return None
        raw.decode_issue = None
        return TransportPacket(raw.timestamp, src, dst, "udp", sport, dport, data[8:length], raw.wire_len, 0,
                               0, raw.frame_number, raw.interface_id)
    return None

"""Generate tiny synthetic captures for demonstrating OTScope without third-party libraries."""
from __future__ import annotations

import socket
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def tcp_frame(src, dst, sport, dport, payload, seq=1):
    src_ip, dst_ip = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 8192, 0, 0)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp_csum = checksum(pseudo + tcp + payload)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 8192, tcp_csum, 0)
    total_len = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 1, 0, 64, 6, 0, src_ip, dst_ip)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    eth = bytes.fromhex("00112233445566778899aabb0800")
    return eth + ip + tcp + payload


def modbus_req(fc, address=0, qty=1, tid=1):
    pdu = bytes([fc]) + struct.pack("!HH", address, qty)
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, 1) + pdu


def iec104_command(type_id=45):
    asdu = bytes([type_id, 1]) + struct.pack("<H", 6) + struct.pack("<H", 1) + b"\x01\x00\x00\x01"
    apdu = b"\x00\x00\x00\x00" + asdu
    return bytes([0x68, len(apdu)]) + apdu


def s7_job(function=0x04):
    s7 = b"\x32\x01\x00\x00\x00\x01\x00\x01\x00\x00" + bytes([function])
    cotp = b"\x02\xf0\x80"
    total = 4 + len(cotp) + len(s7)
    return b"\x03\x00" + struct.pack("!H", total) + cotp + s7


def write_pcap(path: Path, frames):
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        sec = 1_700_000_000
        for i, frame in enumerate(frames):
            fh.write(struct.pack("<IIII", sec + i, 0, len(frame), len(frame)))
            fh.write(frame)


def main():
    baseline = [
        tcp_frame("10.0.0.10", "10.0.0.20", 40000, 502, modbus_req(3, 0, 10, 1)),
        tcp_frame("10.0.0.10", "10.0.0.20", 40000, 502, modbus_req(4, 20, 4, 2)),
        tcp_frame("10.0.0.30", "10.0.0.40", 41000, 2404, iec104_command(102)),
        tcp_frame("10.0.0.50", "10.0.0.60", 42000, 102, s7_job(0x04)),
    ]
    changed = baseline + [
        tcp_frame("10.0.0.10", "10.0.0.20", 40000, 502, modbus_req(16, 100, 3, 3)),
        tcp_frame("10.0.0.77", "10.0.0.20", 43000, 502, modbus_req(6, 101, 1, 4)),
        tcp_frame("10.0.0.30", "10.0.0.40", 41000, 2404, iec104_command(45)),
        tcp_frame("10.0.0.50", "10.0.0.60", 42000, 102, s7_job(0x29)),
    ]
    write_pcap(ROOT / "baseline_demo.pcap", baseline)
    write_pcap(ROOT / "changed_demo.pcap", changed)
    print("Generated baseline_demo.pcap and changed_demo.pcap")


if __name__ == "__main__":
    main()

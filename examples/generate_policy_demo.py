"""Generate an offline lab example with permitted and prohibited Modbus traffic."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

from generate_demo_pcaps import modbus_req, tcp_frame, write_pcap


def generate(out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    frames, sequences = [], {}

    def add(src, dst, sport, dport, payload):
        key = src, dst, sport, dport
        sequence = sequences.get(key, 1)
        frames.append(tcp_frame(src, dst, sport, dport, payload, seq=sequence))
        sequences[key] = sequence + len(payload)

    plc, hmi, engineer, historian = "10.20.40.20", "10.20.10.10", "10.20.20.10", "10.20.30.10"
    # Three permitted requests followed by a service response.
    add(hmi, plc, 40000, 502, modbus_req(3, 0, 10, 1))
    add(engineer, plc, 41000, 502, modbus_req(16, 100, 3, 2))
    add(historian, plc, 42000, 502, modbus_req(3, 20, 2, 3))
    reply_pdu = b"\x03\x14" + b"\x00\x01" * 10
    add(plc, hmi, 502, 40000, struct.pack("!HHHB", 1, 0, len(reply_pdu) + 1, 1) + reply_pdu)
    baseline = out_dir / "policy_baseline.pcap"
    write_pcap(baseline, frames)

    # Frame 5: a historian write violates its read-only rule.
    add(historian, plc, 42000, 502, modbus_req(6, 101, 1, 4))
    # Frame 6: the engineer's permitted write range ends at 102.
    add(engineer, plc, 41000, 502, modbus_req(16, 102, 2, 5))
    # Frame 7: an unconfigured device has no matching allow rule.
    add("10.20.10.77", plc, 43000, 502, modbus_req(3, 0, 1, 6))
    changed = out_dir / "policy_changed.pcap"
    write_pcap(changed, frames)
    return baseline, changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out_dir", nargs="?", type=Path, default=Path("policy-demo"))
    args = parser.parse_args()
    for path in generate(args.out_dir):
        print(path)


if __name__ == "__main__":
    main()

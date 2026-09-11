import csv
import json
import struct

import pytest

from otscope.analyzer import analyze_capture
from otscope.capture import CaptureError, read_capture
from otscope.cli import main
from otscope.protocols import modbus, s7
from otscope.report import write_outputs


def block(kind, body, endian="<"):
    body += b"\0" * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)


def section(endian="<"):
    return block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def enhanced(frame, interface=0, tick=1, endian="<"):
    return block(6, struct.pack(endian + "IIIII", interface, 0, tick, len(frame), len(frame)) + frame, endian)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_byte_order_resolution_offsets_and_frame_numbers(tmp_path, packets, endian):
    frame = packets["tcp_frame"]("10.0.0.10", "10.0.0.20", 40000, 502, packets["modbus_req"](6, 100, 1))
    # nanosecond resolution and an interface timestamp offset of 2 seconds
    options = struct.pack(endian+"HH", 9, 1) + b"\x09\0\0\0"
    options += struct.pack(endian+"HHq", 14, 8, 2)
    interface = block(1, struct.pack(endian+"HHI", 1, 0, 65535) + options, endian)
    path = tmp_path / "input.pcapng"
    path.write_bytes(section(endian) + interface + enhanced(frame, tick=1_000_000_000, endian=endian))
    raw = list(read_capture(path))
    assert raw[0].timestamp == 3.0
    assert raw[0].frame_number == 1
    result = analyze_capture(path)
    assert result["coverage"]["protocol_messages_decoded"]["modbus"] == 1


def test_pcapng_interface_isolation_in_capture_pipeline(tmp_path, packets):
    request = packets["modbus_req"](6, 100, 1)
    first = packets["tcp_frame"]("10.0.0.10", "10.0.0.20", 40000, 502, request[:8])
    second = packets["tcp_frame"]("10.0.0.10", "10.0.0.20", 40000, 502, request[8:], seq=9)
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    path = tmp_path / "interfaces.pcapng"
    path.write_bytes(section() + interface + interface + enhanced(first, 0) + enhanced(second, 1))
    result = analyze_capture(path)
    assert result["coverage"]["protocol_messages_decoded"] == {}
    assert result["coverage"]["tcp_reassembly"]["incomplete_regions"] == 2


@pytest.mark.parametrize("broken", ["trailer", "caplen", "interface"])
def test_invalid_pcapng_lengths_and_interfaces_fail_clearly(tmp_path, packets, broken):
    frame = packets["tcp_frame"]("10.0.0.10", "10.0.0.20", 40000, 502, packets["modbus_req"](6, 100, 1))
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    packet = bytearray(enhanced(frame, 9 if broken == "interface" else 0))
    if broken == "trailer":
        packet[-4:] = b"\0\0\0\0"
    elif broken == "caplen":
        packet[20:24] = struct.pack("<I", 10000)
    path = tmp_path / "bad.pcapng"
    path.write_bytes(section() + interface + packet)
    with pytest.raises(CaptureError):
        analyze_capture(path)


def test_large_timeline_has_no_silent_default_limit(packets, capture, tmp_path):
    request = packets["modbus_req"](3, 0, 1)
    result = analyze_capture(capture([request] * 10005))
    assert len(result["timeline"]) == 10006  # first conversation plus every operation
    assert result["coverage"]["timeline"]["events_omitted"] == 0
    report = write_outputs(result, tmp_path / "report")
    content = report.read_text()
    assert "frame.number in {10005}" in content
    assert "timeline-pages" in content
    with (report.parent / "timeline.csv").open(newline="") as fh:
        assert len(list(csv.DictReader(fh))) == 10006


def test_optional_limit_is_explicit_and_retains_earliest_events(packets, capture):
    result = analyze_capture(capture([packets["modbus_req"](6, n, 1) for n in range(5)]), timeline_limit=2)
    assert result["coverage"]["timeline"] == {"events_total": 6, "events_retained": 2, "events_omitted": 4, "limit": 2}
    assert all(event["evidence"]["frame_numbers"] == [1] for event in result["timeline"])
    assert any("Timeline limited" in text for text in result["coverage"]["warnings"])


def test_cli_exports_timeline_metadata_and_reports_limits(packets, capture, tmp_path, capsys):
    path = capture([packets["modbus_req"](6, 100, 1)])
    out = tmp_path / "timeline.json"
    assert main(["timeline", str(path), "-o", str(out), "--timeline-limit", "0"]) == 0
    assert json.loads(out.read_text()) == []
    metadata = json.loads(out.with_suffix(".metadata.json").read_text())
    assert metadata["capture"]["sha256"]
    assert metadata["coverage"]["timeline"]["events_omitted"] == 2
    assert "warning:" in capsys.readouterr().err


def test_cli_rejects_non_baseline_json(packets, capture, tmp_path, capsys):
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{}")
    path = capture([packets["modbus_req"](6, 100, 1)])
    assert main(["compare", str(invalid), str(path), "-o", str(tmp_path / "report")]) == 2
    assert "Expected an OTScope baseline" in capsys.readouterr().err


def test_report_exposes_evidence_and_escapes_capture_text(packets, capture, tmp_path):
    result = analyze_capture(capture([packets["modbus_req"](6, 100, 1)]))
    result["capture"]["filename"] = "<script>alert(1)</script>"
    evidence = result["timeline"][-1]["evidence"]
    finding = {"severity": "HIGH", "title": "New target", "description": "<img src=x>", "evidence": evidence}
    content = write_outputs(result, tmp_path / "report", [finding]).read_text()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "&lt;img src=x&gt;" in content
    assert result["capture"]["sha256"] in content
    assert "frame.number in {1}" in content
    assert "View evidence" in content


@pytest.mark.parametrize("payload", [
    struct.pack("!HHHBBHH", 1, 0, 6, 1, 16, 100, 3),  # missing FC16 byte count/data
    struct.pack("!HHHBBHH", 1, 0, 6, 1, 3, 0, 0),  # zero quantity
    struct.pack("!HHHBBHH", 1, 0, 6, 1, 3, 65535, 2),  # out-of-range registers
    struct.pack("!HHHBBHH", 1, 0, 100, 1, 6, 100, 1),  # inconsistent MBAP length
])
def test_malformed_modbus_requests_do_not_become_operations(payload):
    assert modbus.parse(payload, request=True) is None


def test_arbitrary_protocol_id_byte_is_not_s7():
    assert s7.parse(b"junk\x32\x01\x00\x00\x00\x01\x00\x01\x00\x00\x29", request=True) is None


def test_truncated_capture_is_explicit(packets, capture):
    path = capture([packets["modbus_req"](6, 100, 1)])
    content = bytearray(path.read_bytes())
    caplen = struct.unpack("<I", content[32:36])[0]
    content[32:36] = struct.pack("<I", caplen-2)
    path.write_bytes(content[:-2])
    result = analyze_capture(path)
    assert result["coverage"]["truncated_packets"] == 1
    assert result["coverage"]["protocol_messages_decoded"] == {}
    assert result["coverage"]["warnings"]


def test_ip_fragments_are_counted_and_not_parsed_as_complete_messages(packets, capture):
    path = capture([packets["modbus_req"](6, 100, 1)])
    content = bytearray(path.read_bytes())
    content[60:62] = b"\x20\x00"  # Ethernet + IPv4 flags/fragment offset
    path.write_bytes(content)
    result = analyze_capture(path)
    assert result["coverage"]["fragmented_ip_packets"] == 1
    assert result["coverage"]["protocol_messages_decoded"] == {}
    assert any("Fragmented IP" in text for text in result["coverage"]["warnings"])

"""Regression tests for baseline loss-of-view and protocol-safe alerting."""
from __future__ import annotations

import copy
import json
import struct

from otscope.analyzer import analyze_capture
from otscope.baseline import merge_baselines
from otscope.cli import main
from otscope.compare import compare
from otscope.protocols import dnp3, iec104, modbus, s7
from otscope.report import write_outputs


def flow(src="a", dst="b", proto="modbus", port=502, semantics=None, rate=1.0, packets=50):
    return {"key": f"{src}|{dst}|tcp|{port}|{proto}", "src": src, "dst": dst,
            "transport": "tcp", "service_port": port, "protocol": proto,
            "packet_rate": rate, "packets": packets, "semantics": semantics or {},
            "evidence": {"frame_numbers": [1]}}


def analysis(*flows):
    ips = {ip for conv in flows for ip in (conv["src"], conv["dst"])}
    return {"tool": "OTScope", "schema_version": 2,
            "assets": [{"ip": ip} for ip in sorted(ips)], "conversations": list(flows),
            "capture": {"sha256": "abc", "duration_seconds": 60, "packets_total": 100},
            "coverage": {"warnings": []}}


def test_missing_polling_conversation_when_both_assets_active():
    missing = flow(src="a", dst="b")
    baseline = analysis(missing, flow(src="a", dst="c", port=80, proto="http"))
    current = analysis(flow(src="a", dst="c", port=80, proto="http"),
                       flow(src="b", dst="c", port=80, proto="http"))
    f = compare(baseline, current)
    assert any(x["kind"] == "missing_conversation" and x["severity"] == "HIGH" and
               x["evidence"]["conversation"] == missing["key"] for x in f)
    current["assets"] = [x for x in current["assets"] if x["ip"] != "b"]
    assert not any(x["kind"] == "missing_conversation" for x in compare(baseline, current))


def test_dropped_rate_and_unchanged_rate():
    baseline = analysis(flow(rate=12, packets=100))
    current = analysis(flow(rate=1, packets=2))
    assert any(f["kind"] == "rate_decrease" for f in compare(baseline, current))
    assert not any(f["kind"] == "rate_decrease" for f in compare(baseline, analysis(flow(rate=12))))
    assert any(f["kind"] == "rate_decrease" for f in compare(baseline, analysis(flow(rate=None, packets=1))))


def test_iec104_activation_command_not_confirmation():
    ca = flow(proto="iec104", port=2404, semantics={"type_ids": [45], "activations": [45],
                "activation_evidence": {"45": {"frame_numbers": [2]}}, "access": ["command"]})
    response = flow(src="b", dst="a", proto="iec104", port=2404,
                    semantics={"type_ids": [45], "confirmations": [45],
                               "confirmation_evidence": {"45": {"frame_numbers": [3]}}})
    baseline = analysis(flow(proto="iec104", port=2404), flow(src="b", dst="a", proto="iec104", port=2404))
    found = compare(baseline, analysis(ca, response))
    assert len([x for x in found if x["severity"] == "CRITICAL"]) == 1
    activation = next(x for x in found if x["kind"] == "new_iec104_command")
    assert activation["evidence"]["activation_confirmation"]["frame_numbers"] == [3]
    assert any(x["kind"] == "new_iec104_type" and x["severity"] == "INFO" for x in found)


def test_iec104_interrogation_and_reset_different_severities():
    baseline = analysis(flow(proto="iec104", port=2404))
    curr = analysis(flow(proto="iec104", port=2404,
                         semantics={"type_ids": [100, 105], "activations": [100, 105]}))
    got = compare(baseline, curr)
    assert any(x["kind"] == "new_iec104_system_command" and x["severity"] == "LOW" for x in got)
    assert any(x["kind"] == "new_iec104_reset_process" and x["severity"] == "CRITICAL" for x in got)
    asdu = b"\x2d\x01\x07\x00\x01\x00\x01\x00\x00\x01"
    payload = bytes([0x68, len(asdu)+4]) + b"\0"*4 + asdu
    assert iec104.parse(payload, request=False)["access"] == "confirmation"


def dnp3_frame(function: int, corrupt=False) -> bytes:
    app_data = bytes([0xC0, 0xC0, function])
    header = b"\x05\x64" + bytes([5 + len(app_data), 0xC4]) + struct.pack("<HH", 11, 12)
    header += struct.pack("<H", dnp3._crc(header))
    packet = header + app_data + struct.pack("<H", dnp3._crc(app_data))
    return packet[:-1] + b"\0" if corrupt else packet


def test_dnp3_crc_and_function_operations(capture):
    operation = dnp3_frame(5)
    parsed = dnp3.parse(operation, request=True)
    assert parsed["function_code"] == 5 and parsed["access"] == "control"
    assert parsed["link_source"] == 12 and parsed["link_destination"] == 11
    assert dnp3.parse(dnp3_frame(5, corrupt=True), request=True) is None
    current = analyze_capture(capture([operation], port=20000))
    assert current["coverage"]["protocol_messages_decoded"]["dnp3"] == 1
    assert 5 in current["conversations"][0]["semantics"]["request_function_codes"]
    baseline = copy.deepcopy(current)
    baseline["conversations"][0]["semantics"]["request_function_codes"] = [1]
    found = compare(baseline, current)
    assert any(x["kind"] == "new_dnp3_function" and x["severity"] == "CRITICAL" for x in found)


def test_dnp3_segmented_not_claimed_decoded(capture):
    frame = bytearray(dnp3_frame(3))
    frame[10] = 0x80  # transport FIN but no FIR
    frame[-2:] = struct.pack("<H", dnp3._crc(frame[10:-2]))
    result = analyze_capture(capture([bytes(frame)], port=20000))
    assert result["coverage"]["dnp3_fragments_not_decoded"] == 1
    assert not result["coverage"]["protocol_messages_decoded"].get("dnp3")


def test_modbus_diagnostics_device_id_and_umas():
    def mb(fc, pdu):
        return struct.pack("!HHHB", 1, 0, len(pdu)+2, 1) + bytes([fc]) + pdu
    assert modbus.parse(mb(8, b"\x00\x04\x00\x00"), request=True)["diagnostic_subfunction"] == 4
    assert modbus.parse(mb(43, b"\x0e\x01"), request=True)["device_identification"]
    assert modbus.parse(mb(90, b"\x01\x02"), request=True)["access"] == "engineering"
    baseline = analysis(flow(semantics={"request_function_codes": [3]}))
    cur = analysis(flow(semantics={"request_function_codes": [3, 8], "diagnostic_subfunctions": [4]}))
    assert any(f["kind"] == "modbus_listen_only" for f in compare(baseline, cur))


def test_s7comm_plus_and_userdata(capture):
    cotp = b"\x02\xf0\x80"
    blob = b"\x72\x02\x00\x00\x00\x00"
    raw = b"\x03\x00" + struct.pack("!H", 4+len(cotp)+len(blob)) + cotp + blob
    assert s7.parse(raw, request=True)["decode_status"] == "present_not_decoded"
    observed = analyze_capture(capture([raw], port=102))
    assert observed["conversations"][0]["protocol"] == "s7comm-plus"
    assert observed["coverage"]["s7comm_plus_messages_not_decoded"] == 1
    userdata = b"\x32\x07\0\0\0\x01\0\x04\0\0\0\x01\x14\x01"
    parsed = s7.parse(userdata, request=True)
    assert parsed["rosctr"] == 7 and parsed["userdata_group"] == 4


def test_write_value_outside_observed_range():
    baseline = analysis(flow(semantics={"write_value_ranges": {"1:holding_register:7": {"min": 20, "max": 40, "samples": 6}}}))
    current = analysis(flow(semantics={"write_value_ranges": {"1:holding_register:7": {"min": 100, "max": 100, "samples": 1}}}))
    findings = compare(baseline, current)
    assert any(x["kind"] == "modbus_write_value_outlier" and x["severity"] == "HIGH" for x in findings)
    assert "NOT a validated physical safety limit" in next(x["description"] for x in findings if x["kind"] == "modbus_write_value_outlier")


def test_rhythm_anomaly_signature():
    stable = {"signature": "FC3:unit1:addr0:qty1", "samples": 15, "median_seconds": 1,
              "mad_seconds": 0.05, "interval_sample_seconds": [1] * 15}
    changed = {**stable, "median_seconds": 4, "interval_sample_seconds": [4] * 15}
    b = analysis(flow(semantics={"interval_profiles": [stable]}))
    c = analysis(flow(semantics={"interval_profiles": [changed]}))
    assert any(x["kind"] == "polling_rhythm_change" for x in compare(b, c))


def test_baseline_merge_preserves_union_and_value_bounds(tmp_path):
    a = analysis(flow(semantics={"request_function_codes": [3], "write_value_ranges": {"1:holding_register:7": {"min": 10, "max": 30, "samples": 3}}}))
    b = analysis(flow(semantics={"request_function_codes": [6], "write_value_ranges": {"1:holding_register:7": {"min": 5, "max": 40, "samples": 4}}}))
    joined = merge_baselines([a, b])
    sem = joined["conversations"][0]["semantics"]
    assert sem["request_function_codes"] == [3, 6]
    assert sem["write_value_ranges"]["1:holding_register:7"] == {"min": 5, "max": 40, "samples": 7}
    assert len(joined["baseline_sources"]) == 2
    aa, bb = tmp_path/'a.json', tmp_path/'b.json'
    aa.write_text(json.dumps(a))
    bb.write_text(json.dumps(b))
    merged_file = tmp_path/'out.json'
    assert main(["baseline", "merge", str(aa), str(bb), "-o", str(merged_file)]) == 0
    assert merged_file.exists()


def test_explicit_port_override_and_jsonlines(capture, packets, tmp_path):
    data = packets["modbus_req"](3, 0, 1)
    path = capture([data], port=5020)
    assert analyze_capture(path)["conversations"][0]["protocol"] == "modbus"  # payload signature
    assert main(["analyze", str(path), "--port-map", "modbus=5020", "-o", str(tmp_path/'report')]) == 0
    out = write_outputs(analyze_capture(path), tmp_path/'comparison', findings=[{
        "kind": "new_modbus_function", "severity": "HIGH", "title": "Test", "description": "Defensive test",
        "techniques": [{"id": "T0836", "name": "Modify Parameter"}], "evidence": {"src": "10.0.0.10"}}])
    assert 'T0836' in out.read_text()
    events = (out.parent/'findings.ecs.ndjson').read_text().splitlines()
    assert json.loads(events[0])["source"]["ip"] == "10.0.0.10"

import copy
import csv
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from otscope.analyzer import analyze_capture
from otscope.cli import main
from otscope.compare import compare
from otscope.policy import NetworkPolicy, PolicyError, load_policy
from otscope.report import write_outputs
from otscope.topology import build_topology

ROOT = Path(__file__).parents[1]


@pytest.fixture
def document():
    return {
        "schema_version": 1, "name": "Test plant", "default_action": "deny",
        "zones": [{"id": "operations", "networks": ["10.0.0.0/24"]}, {"id": "control"}],
        "assets": [{"id": "hmi", "ip": "10.0.0.10", "name": "Operator HMI"},
                   {"id": "plc", "ip": "10.0.0.20", "name": "PLC", "zone": "control"}],
        "conduits": [{"id": "operator-control", "source_zone": "operations", "destination_zone": "control"}],
        "rules": [{"id": "hmi-read", "source": {"asset": "hmi"}, "destination": {"asset": "plc"},
                   "protocol": "modbus", "action": "allow", "conduit": "operator-control",
                   "modbus": {"function_codes": [3], "unit_ids": [1], "access": ["read"],
                              "address_ranges": [{"space": "holding_register", "access": "read", "start": 0, "end": 99}]}}],
    }


def assessed(document, capture, payloads):
    return analyze_capture(capture(payloads), policy=NetworkPolicy(document))


def test_policy_assigns_names_zones_and_conduit(document, capture, packets):
    result = assessed(document, capture, [packets["modbus_req"](3, 0, 10)])
    assert result["policy"]["findings"] == []
    assert result["policy"]["summary"]["requests_checked"] == 1
    assert not result["policy"]["summary"]["semantic_coverage_incomplete"]
    hmi, plc = result["assets"]
    assert hmi["zone_id"] == "operations"
    assert plc["zone_id"] == "control"  # explicit assignment overrides CIDR membership
    assert result["conversations"][0]["policy"] == {
        "status": "observed_operations_permitted", "requests_checked": 1, "unknown_operations": 0,
        "violations": 0, "conduit_id": "operator-control", "rule_id": "hmi-read",
    }


@pytest.mark.parametrize("constraints,payload_args,unit,reason", [
    ({"function_codes": [3]}, (6, 0, 1), 1, "Function code"),
    ({"unit_ids": [1]}, (3, 0, 1), 2, "Unit ID"),
    ({"access": ["read"]}, (16, 0, 1), 1, "access type"),
    ({"address_ranges": [{"space": "holding_register", "access": "read", "start": 0, "end": 9}]},
     (3, 9, 2), 1, "outside the permitted ranges"),
    ({"address_ranges": [{"space": "holding_register", "access": "read", "start": 0, "end": 9}]},
     (1, 0, 1), 1, "address space"),
])
def test_operation_constraints(document, capture, packets, constraints, payload_args, unit, reason):
    document["rules"][0]["modbus"] = constraints
    payload = bytearray(packets["modbus_req"](*payload_args))
    payload[6] = unit
    result = assessed(document, capture, [bytes(payload)])
    finding, = result["policy"]["findings"]
    assert finding["kind"] == "policy_operation_denied"
    assert reason in finding["description"]
    assert finding["evidence"]["current"]["frame_numbers"] == [1]
    assert finding["evidence"]["policy_sha256"] == result["policy"]["sha256"]
    assert finding["evidence"]["current_capture_sha256"] == result["capture"]["sha256"]


def test_adjacent_permitted_ranges_are_combined(document, capture, packets):
    document["rules"][0]["modbus"]["address_ranges"] = [
        {"space": "holding_register", "access": "read", "start": 0, "end": 4},
        {"space": "holding_register", "access": "read", "start": 5, "end": 9},
    ]
    assert not assessed(document, capture, [packets["modbus_req"](3, 0, 10)])["policy"]["findings"]
    document["rules"][0]["modbus"]["address_ranges"][1]["start"] = 6
    assert assessed(document, capture, [packets["modbus_req"](3, 0, 10)])["policy"]["findings"]


def test_fc23_checks_both_read_and_write_targets(document, capture):
    pdu = b"\x17" + struct.pack("!HHHHB", 0, 2, 100, 1, 2) + b"\x00\x01"
    payload = struct.pack("!HHHB", 1, 0, len(pdu) + 1, 1) + pdu
    document["rules"][0]["modbus"] = {
        "function_codes": [23], "access": ["read", "write"],
        "address_ranges": [{"space": "holding_register", "access": "read", "start": 0, "end": 9},
                           {"space": "holding_register", "access": "write", "start": 100, "end": 102}],
    }
    assert not assessed(document, capture, [payload])["policy"]["findings"]
    document["rules"][0]["modbus"]["access"] = ["write"]
    finding, = assessed(document, capture, [payload])["policy"]["findings"]
    assert finding["evidence"]["operation"]["access"] == ["read", "write"]
    document["rules"][0]["modbus"]["access"] = ["read", "write"]
    document["rules"][0]["modbus"]["address_ranges"][0]["end"] = 0
    assert assessed(document, capture, [payload])["policy"]["findings"]


def test_first_matching_flow_rule_is_authoritative(document, capture, packets):
    permissive = copy.deepcopy(document["rules"][0])
    permissive["id"] = "fallback"
    permissive.pop("modbus")
    document["rules"].append(permissive)
    result = assessed(document, capture, [packets["modbus_req"](6, 0, 1)])
    assert result["policy"]["findings"][0]["evidence"]["rule_id"] == "hmi-read"
    document["rules"].reverse()
    assert not assessed(document, capture, [packets["modbus_req"](6, 0, 1)])["policy"]["findings"]


@pytest.mark.parametrize("selector", [{"zone": "operations"}, {"network": "10.0.0.0/24"}, {"any": True}])
def test_endpoint_selectors(document, capture, packets, selector):
    document["rules"][0]["source"] = selector
    assert not assessed(document, capture, [packets["modbus_req"](3, 0, 1)])["policy"]["findings"]


def test_ipv6_network_and_asset_resolution(document):
    document["zones"][0]["networks"] = ["2001:db8:1::/64"]
    document["assets"][0]["ip"] = "2001:db8:1:0::10"
    policy = NetworkPolicy(document)
    assert policy.resolve("2001:db8:1::10")["asset_id"] == "hmi"
    assert policy.resolve("2001:db8:1::77")["zone_id"] == "operations"
    assert policy.resolve("2001:db8:2::77")["zone_id"] is None


@pytest.mark.parametrize("field,value", [("protocol", "s7comm"), ("transport", "udp"), ("service_port", 503)])
def test_unmatched_default_actions(document, capture, packets, field, value):
    document["rules"][0].pop("modbus")
    document["rules"][0][field] = value
    payload = packets["modbus_req"](3, 0, 1)
    denied = assessed(document, capture, [payload])
    assert denied["policy"]["findings"][0]["kind"] == "policy_flow_denied"
    assert denied["policy"]["findings"][0]["evidence"]["rule_id"] is None
    document["default_action"] = "observe"
    observed = assessed(document, capture, [payload])
    assert observed["policy"]["summary"]["unmatched_flows"] == 1
    assert not observed["policy"]["findings"]


def test_conduits_are_directional_and_deny_rules_have_severity(document, capture, packets):
    document["conduits"][0].update(source_zone="control", destination_zone="operations")
    result = assessed(document, capture, [packets["modbus_req"](3, 0, 1)])
    assert result["policy"]["findings"][0]["evidence"]["rule_id"] is None
    document["rules"][0].pop("conduit")
    document["rules"][0].pop("modbus")
    document["rules"][0].update(action="deny", severity="CRITICAL")
    result = assessed(document, capture, [packets["modbus_req"](3, 0, 1)])
    assert result["policy"]["findings"][0]["severity"] == "CRITICAL"
    assert result["policy"]["findings"][0]["evidence"]["rule_id"] == "hmi-read"


@pytest.mark.parametrize("payload", [
    struct.pack("!HHHBB", 1, 0, 2, 1, 43),  # unsupported target layout
    struct.pack("!HHHBBHH", 1, 0, 6, 1, 3, 0, 0),  # malformed zero-quantity read
    b"\x00\x01\x00\x00\x00\x06\x01\x03",  # incomplete message
    b"",  # flow with no operation bytes
])
def test_undecoded_operations_are_not_reported_as_permitted(document, capture, payload):
    document["rules"][0]["modbus"].pop("function_codes")
    document["rules"][0]["modbus"].pop("access")
    result = assessed(document, capture, [payload])
    assert not result["policy"]["findings"]
    assert result["policy"]["summary"]["flows_not_evaluated"] == 1


def test_decoded_then_malformed_marks_flow_and_coverage_incomplete(document, capture, packets):
    result = assessed(document, capture, [packets["modbus_req"](3, 0, 1), packets["modbus_req"](3, 0, 0)])
    assert result["policy"]["summary"]["requests_checked"] == 1
    assert result["policy"]["summary"]["flows_not_evaluated"] == 1
    assert result["policy"]["summary"]["semantic_coverage_incomplete"]


def test_split_retransmitted_request_preserves_evidence(document, capture, packets):
    payload = packets["modbus_req"](6, 100, 1)
    result = analyze_capture(capture([payload[:8], payload[8:], payload[:8]], seqs=[1, 9, 1]),
                             timeline_limit=0, policy=NetworkPolicy(document))
    finding, = result["policy"]["findings"]
    assert result["timeline"] == []
    assert finding["evidence"]["occurrences"] == 1
    assert finding["evidence"]["current"]["frame_numbers"] == [1, 2]
    assert "frame.number in {1 2}" == finding["evidence"]["current"]["wireshark_filter"]


def test_policy_not_suppressed_by_baseline_or_timeline_cap(document, capture, packets, tmp_path):
    path = capture([packets["modbus_req"](6, 100, 1)] * 25)
    baseline = analyze_capture(path, timeline_limit=0)
    current = analyze_capture(path, timeline_limit=0, policy=NetworkPolicy(document))
    finding, = current["policy"]["findings"]
    assert finding["evidence"]["occurrences"] == 25
    assert finding["evidence"]["current"]["frame_numbers"] == list(range(1, 21))
    assert finding["evidence"]["current"]["frames_sample_limited"]
    assert finding["evidence"]["current"]["last_seen"] > finding["evidence"]["current"]["first_seen"]
    # Timeline coverage warnings can be returned; no new operations are introduced.
    assert not any(f["kind"].startswith("new_") for f in compare(baseline, current))
    bp, pp = tmp_path / "baseline.json", tmp_path / "policy.json"
    bp.write_text(json.dumps(baseline))
    pp.write_text(json.dumps(document))
    assert main(["compare", str(bp), str(path), "--policy", str(pp),
                 "--timeline-limit", "0", "--fail-on-policy", "-o", str(tmp_path / "out")]) == 1
    assert any(f["kind"] == "policy_operation_denied" for f in json.loads((tmp_path / "out/findings.json").read_text()))


def test_reply_only_capture_is_explicitly_unassessed(document, packets, tmp_path):
    path = tmp_path / "reply.pcap"
    reply = struct.pack("!HHHBBBB", 1, 0, 4, 1, 3, 1, 0)
    packets["write_pcap"](path, [packets["tcp_frame"]("10.0.0.20", "10.0.0.10", 502, 40000, reply)])
    result = analyze_capture(path, policy=NetworkPolicy(document))
    assert not result["policy"]["findings"]
    assert result["policy"]["summary"]["response_directions"] == 1
    assert result["policy"]["summary"]["requests_checked"] == 0
    assert result["conversations"][0]["policy"]["status"] == "response_direction"


@pytest.mark.parametrize("path,value", [
    (("schema_version",), True), (("default_action",), "allow"), (("rules",), {}),
    (("unknown",), 1), (("zones", 0, "networks"), ["10.0.0.1/24"]),
    (("assets", 0, "zone"), "missing"), (("assets", 0, "zone"), []),
    (("rules", 0, "source"), {"any": 1}), (("rules", 0, "source"), {"any": True, "zone": "operations"}),
    (("rules", 0, "modbus", "unit_ids"), [True]), (("rules", 0, "modbus", "unit_ids"), [256]),
    (("rules", 0, "modbus", "function_codes"), []), (("rules", 0, "modbus", "access"), ["read", "read"]),
    (("rules", 0, "modbus", "address_ranges", 0, "end"), -1),
    (("rules", 0, "modbus", "address_ranges", 0, "space"), "register"),
    (("rules", 0, "conduit"), "missing"), (("rules", 0, "severity"), []),
    (("rules", 0, "service_port"), True), (("rules", 0, "modbus"), {}),
    (("rules", 0, "action"), "deny"), (("rules", 0, "protocol"), "tcp"),
])
def test_invalid_policy_fails_before_capture_analysis(document, path, value):
    parent = document
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(PolicyError):
        NetworkPolicy(document)


@pytest.mark.parametrize("field", ["assets", "rules", "conduits"])
def test_duplicate_ids_are_rejected(document, field):
    document[field].append(copy.deepcopy(document[field][0]))
    with pytest.raises(PolicyError):
        NetworkPolicy(document)


def test_overlapping_zone_cidrs_are_rejected(document):
    document["zones"][1]["networks"] = ["10.0.0.0/25"]
    with pytest.raises(PolicyError, match="Overlapping"):
        NetworkPolicy(document)


def test_duplicate_json_keys_are_rejected(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text('{"schema_version": 1, "schema_version": 2}')
    with pytest.raises(PolicyError, match="Duplicate JSON key"):
        load_policy(path)


def test_policy_hash_ignores_formatting_and_input_mutation(document, tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document, indent=4, sort_keys=True))
    policy = NetworkPolicy(document)
    assert load_policy(path).sha256 == policy.sha256
    document["rules"][0]["modbus"]["unit_ids"] = [2]
    assert policy.rules[0]["modbus"]["unit_ids"] == [1]
    assert NetworkPolicy(document).sha256 != policy.sha256


def test_cli_validates_and_returns_meaningful_status(document, capture, packets, tmp_path, capsys):
    pp = tmp_path / "policy.json"
    pp.write_text(json.dumps(document))
    assert main(["validate-policy", str(pp)]) == 0
    assert "Policy valid" in capsys.readouterr().out
    path = capture([packets["modbus_req"](3, 0, 1)])
    out = tmp_path / "out"
    assert main(["analyze", str(path), "--policy", str(pp), "--fail-on-policy", "-o", str(out)]) == 0
    bad = capture([packets["modbus_req"](3, 0, 0)])
    assert main(["analyze", str(bad), "--policy", str(pp), "--fail-on-policy", "-o", str(out)]) == 1
    assert main(["analyze", str(path), "--fail-on-policy", "-o", str(out)]) == 2
    pp.write_text('{"mistake": true}')
    assert main(["analyze", "nonexistent.pcap", "--policy", str(pp), "-o", str(tmp_path / "invalid")]) == 2
    assert not (tmp_path / "invalid").exists()


def test_exports_safe_labels_complete_graph_and_policy_evidence(document, capture, packets, tmp_path):
    document["assets"][0]["name"] = '</script><img src=x onerror="alert(1)">'
    document["assets"][1]["name"] = "=1+1"
    result = assessed(document, capture, [packets["modbus_req"](6, 0, 1)])
    report = write_outputs(result, tmp_path / "report")
    content = report.read_text()
    assert document["assets"][0]["name"] not in content
    assert r"\u003c/script>" in content
    assert "Policy assessment" in content
    graph = json.loads((report.parent / "topology.json").read_text())
    assert graph == build_topology(result)
    assert graph["nodes"][0]["label"] == document["assets"][0]["name"]
    assert graph["edges"][0]["findings"][0]["kind"] == "policy_operation_denied"
    assert json.loads((report.parent / "policy_findings.json").read_text()) == result["policy"]["findings"]
    with (report.parent / "zone_matrix.csv").open(newline="") as fh:
        row, = list(csv.DictReader(fh))
    assert row["destination_name"] == "'=1+1"
    assert row["policy_status"] == "violation"
    assert row["source_zone"] == "operations"


def test_worked_example_matches_documented_findings(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "examples/generate_policy_demo.py"), str(tmp_path)], check=True)
    policy = load_policy(ROOT / "examples/lab_policy.json")
    baseline = analyze_capture(tmp_path / "policy_baseline.pcap", policy=policy)
    assert baseline["policy"]["findings"] == []
    assert baseline["policy"]["summary"]["requests_checked"] == 3
    changed = analyze_capture(tmp_path / "policy_changed.pcap", policy=policy)
    findings = changed["policy"]["findings"]
    assert len(findings) == 3
    assert sorted(f["evidence"]["current"]["frame_numbers"][0] for f in findings) == [5, 6, 7]
    assert {f["evidence"]["rule_id"] for f in findings} == {None, "engineering-writes", "historian-reads"}
    assert changed["policy"]["summary"]["response_directions"] == 1

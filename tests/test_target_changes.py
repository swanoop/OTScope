import copy

from otscope.analyzer import analyze_capture
from otscope.compare import compare


def test_same_function_new_write_register_is_detected_with_evidence(packets, capture):
    baseline = analyze_capture(capture([packets["modbus_req"](6, 100, 1)]))
    current = analyze_capture(capture([packets["modbus_req"](6, 900, 1)]))
    finding = next(f for f in compare(baseline, current) if f["kind"] == "new_modbus_write_target")
    assert finding["evidence"]["new_ranges"] == [{"start": 900, "end": 900}]
    assert finding["evidence"]["baseline_ranges"] == [{"start": 100, "end": 100}]
    assert finding["evidence"]["current"]["frame_numbers"] == [1]
    assert finding["evidence"]["current_capture_sha256"] == current["capture"]["sha256"]


def test_same_function_new_unit_is_detected(packets, capture):
    request = packets["modbus_req"](6, 100, 1)
    changed = request[:6] + b"\x02" + request[7:]
    findings = compare(analyze_capture(capture([request])), analyze_capture(capture([changed])))
    finding = next(f for f in findings if f["kind"] == "new_modbus_unit")
    assert finding["evidence"]["unit_id"] == 2
    assert finding["evidence"]["current"]["frame_numbers"] == [1]


def test_new_unit_target_association_is_detected_even_when_both_units_known(packets, capture):
    unit1 = packets["modbus_req"](6, 100, 1)
    unit2 = packets["modbus_req"](6, 900, 1)
    unit2 = unit2[:6] + b"\x02" + unit2[7:]
    changed = packets["modbus_req"](6, 900, 1)
    findings = compare(analyze_capture(capture([unit1, unit2])), analyze_capture(capture([changed])))
    assert any(f["kind"] == "new_modbus_write_target" for f in findings)


def test_baseline_range_union_allows_different_request_sizes(packets, capture):
    baseline = analyze_capture(capture([packets["modbus_req"](16, 100, 3), packets["modbus_req"](16, 103, 3)]))
    current = analyze_capture(capture([packets["modbus_req"](16, 101, 4)]))
    assert compare(baseline, current) == []


def test_only_unobserved_part_of_expanded_range_is_reported(packets, capture):
    baseline = analyze_capture(capture([packets["modbus_req"](16, 100, 3)]))
    current = analyze_capture(capture([packets["modbus_req"](16, 101, 4)]))
    finding = next(f for f in compare(baseline, current) if f["kind"] == "new_modbus_write_target")
    assert finding["evidence"]["new_ranges"] == [{"start": 103, "end": 104}]


def test_reading_a_register_does_not_baseline_writing_it(packets, capture):
    baseline = analyze_capture(capture([packets["modbus_req"](3, 900, 1), packets["modbus_req"](6, 100, 1)]))
    current = analyze_capture(capture([packets["modbus_req"](6, 900, 1)]))
    assert any(f["kind"] == "new_modbus_write_target" for f in compare(baseline, current))


def test_coils_do_not_allow_holding_register_addresses(packets, capture):
    baseline = analyze_capture(capture([packets["modbus_req"](5, 900, 0), packets["modbus_req"](6, 100, 1)]))
    current = analyze_capture(capture([packets["modbus_req"](6, 900, 1)]))
    assert any(f["kind"] == "new_modbus_write_target" for f in compare(baseline, current))


def test_legacy_baseline_does_not_invent_unit_specific_ranges(packets, capture):
    baseline = analyze_capture(capture([packets["modbus_req"](6, 100, 1)]))
    legacy = copy.deepcopy(baseline)
    legacy["schema_version"] = 1
    for conversation in legacy["conversations"]:
        conversation["semantics"].pop("targets")
    current = analyze_capture(capture([packets["modbus_req"](6, 900, 1)]))
    findings = compare(legacy, current)
    assert any(f["kind"] == "baseline_target_detail_unavailable" for f in findings)
    assert not any(f["kind"] == "new_modbus_write_target" for f in findings)


def test_limited_timeline_does_not_remove_finding_evidence(packets, capture):
    baseline = analyze_capture(capture([packets["modbus_req"](6, 100, 1)]), timeline_limit=0)
    current = analyze_capture(capture([packets["modbus_req"](6, 900, 1)]), timeline_limit=0)
    finding = next(f for f in compare(baseline, current) if f["kind"] == "new_modbus_write_target")
    assert current["timeline"] == []
    assert finding["evidence"]["current"]["frame_numbers"] == [1]


def test_baseline_coverage_warnings_are_carried_into_comparison(packets, capture):
    baseline = analyze_capture(capture([packets["modbus_req"](6, 100, 1)]), timeline_limit=0)
    current = analyze_capture(capture([packets["modbus_req"](6, 100, 1)]))
    warning = next(f for f in compare(baseline, current) if f["kind"] == "baseline_coverage_warning")
    assert warning["evidence"]["warnings"] == baseline["coverage"]["warnings"]

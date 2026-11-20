from __future__ import annotations

from typing import Any

from .models import Finding
from .protocols.iec104 import CONTROL_TYPES, SYSTEM_TYPES, RESET_TYPES
from .protocols.modbus import WRITE_FUNCTIONS
from .protocols.s7 import WRITE_OR_ENGINEERING
from .protocols.dnp3 import SENSITIVE_FUNCTIONS as DNP3_SENSITIVE, RESTART_FUNCTIONS as DNP3_RESTART

OT_PROTOCOLS = {"modbus", "iec104", "s7comm", "s7comm-plus", "dnp3", "ethernet-ip", "ethernet-ip-io", "opc-ua", "bacnet"}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def compare(baseline: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[Finding] = []
    base_assets = {x["ip"] for x in baseline.get("assets", [])}
    current_assets = {x["ip"] for x in current.get("assets", [])}

    for ip in sorted(current_assets - base_assets):
        findings.append(Finding("MEDIUM", "new_asset", f"New asset observed: {ip}", "The asset did not appear in the baseline capture.", {"ip": ip}))
    for ip in sorted(base_assets - current_assets):
        findings.append(Finding("INFO", "missing_asset", f"Baseline asset not observed: {ip}", "The asset appeared in the baseline but not in the current capture.", {"ip": ip}))

    base_conv = {x["key"]: x for x in baseline.get("conversations", [])}
    current_conv = {x["key"]: x for x in current.get("conversations", [])}

    for finding in findings:
        source = baseline if finding.kind == "missing_asset" else current
        sample = next((c.get("evidence", {}) for c in source.get("conversations", [])
                       if finding.evidence["ip"] in (c.get("src"), c.get("dst"))), {})
        finding.evidence["baseline" if finding.kind == "missing_asset" else "current"] = sample
    if baseline.get("coverage", {}).get("warnings"):
        findings.append(Finding("INFO", "baseline_coverage_warning", "Baseline analysis reported coverage warnings",
                                "Review the baseline warnings when interpreting differences or the absence of findings.",
                                {"warnings": baseline["coverage"]["warnings"]}))
    if any(c.get("semantics", {}).get("targets") and
           "targets" not in base_conv.get(key, {}).get("semantics", {})
           for key, c in current_conv.items() if key in base_conv):
        findings.append(Finding("INFO", "baseline_target_detail_unavailable",
                                "Baseline lacks detailed Modbus target evidence",
                                "Detailed address comparisons require decoded baseline targets. Recreate version 0.1 baselines with the current tool; for newer baselines, review capture coverage. Existing function and unit comparisons still run."))

    # Do not call an absent relationship a loss-of-view unless BOTH endpoints
    # were still observed in the new capture. This also avoids duplicate
    # findings for assets missing altogether.
    for key, old in base_conv.items():
        if key in current_conv or old.get("src") not in current_assets or old.get("dst") not in current_assets:
            continue
        sev = "HIGH" if old.get("protocol") in OT_PROTOCOLS else "MEDIUM"
        findings.append(Finding(sev, "missing_conversation",
                                f"Baseline {old.get('protocol')} relationship not observed",
                                f"{old.get('src')} -> {old.get('dst')} on service port {old.get('service_port')} "
                                "was present in the baseline but absent in the current capture, "
                                "although both endpoints were observed. This is a possible loss-of-view signal, "
                                "not proof of an outage.",
                                {"conversation": key, "src": old.get("src"), "dst": old.get("dst"),
                                 "baseline": old.get("evidence", {}),
                                 "baseline_packets": old.get("packets"),
                                 "current_capture_duration_seconds": current.get("capture", {}).get("duration_seconds"),
                                 "current_endpoints_observed": True}))

    for key, conv in current_conv.items():
        first_finding = len(findings)
        old = base_conv.get(key)
        if old is None:
            sev = "HIGH" if conv.get("protocol") in OT_PROTOCOLS else "MEDIUM"
            findings.append(Finding(sev, "new_conversation", f"New {conv.get('protocol')} communication", f"{conv.get('src')} -> {conv.get('dst')} on service port {conv.get('service_port')} was not present in the baseline.", {"conversation": key}))
            _new_semantic_findings(findings, {}, conv)
            _attach_evidence(findings[first_finding:], {}, conv)
            continue
        _new_semantic_findings(findings, old, conv)
        if conv.get("protocol") == "modbus":
            _modbus_target_findings(findings, old, conv)
            _modbus_value_findings(findings, old, conv)
        _rhythm_drift(findings, old, conv)
        _rate_drift(findings, old, conv, baseline.get("capture", {}), current.get("capture", {}))
        _attach_evidence(findings[first_finding:], old, conv)

    _link_iec104_confirmations(findings, current_conv)
    for finding in findings:
        finding.techniques = _techniques_for(finding)
        finding.evidence["baseline_capture_sha256"] = baseline.get("capture", {}).get("sha256")
        finding.evidence["current_capture_sha256"] = current.get("capture", {}).get("sha256")

    return [f.to_dict() for f in sorted(findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.title))]


def _attach_evidence(findings: list[Finding], old: dict, current: dict) -> None:
    for finding in findings:
        sample_key = {
            "new_modbus_write": "write", "new_iec104_command": "command",
            "new_iec104_reset_process": "reset", "new_iec104_system_command": "system",
            "new_s7_change_operation": "engineering",
        }.get(finding.kind)
        for field, prefix in (("function_code", "function"), ("function", "function"),
                              ("type_id", "type"), ("unit_id", "unit")):
            if field in finding.evidence:
                sample_key = f"{prefix}:{finding.evidence[field]}"
        samples = current.get("semantics", {}).get("operation_evidence", {})
        if finding.kind == "new_s7_change_operation" and sample_key not in samples:
            sample_key = "write"
        if finding.kind.startswith("new_iec104") and "type_id" in finding.evidence:
            sample_key = f"type:{finding.evidence['type_id']}"
        finding.evidence.setdefault("current", samples.get(sample_key, current.get("evidence", {})))
        finding.evidence.setdefault("baseline", old.get("evidence", {}))
        finding.evidence["conversation"] = current.get("key")


def _uncovered(start: int, end: int, ranges: list[dict]) -> list[dict]:
    """Subtract the union of observed baseline intervals from an inclusive range."""
    cursor, missing = start, []
    for interval in sorted(ranges, key=lambda x: (x["start"], x["end"])):
        if interval["end"] < cursor:
            continue
        if interval["start"] > end:
            break
        if interval["start"] > cursor:
            missing.append({"start": cursor, "end": min(end, interval["start"]-1)})
        cursor = max(cursor, interval["end"]+1)
        if cursor > end:
            break
    if cursor <= end:
        missing.append({"start": cursor, "end": end})
    return missing


def _modbus_target_findings(findings: list[Finding], old: dict, current: dict) -> None:
    old_s, cur_s = old.get("semantics", {}), current.get("semantics", {})
    old_units = set(old_s.get("request_unit_ids", old_s.get("unit_ids", [])))
    cur_units = set(cur_s.get("request_unit_ids", cur_s.get("unit_ids", [])))
    for unit in sorted(cur_units-old_units):
        writes = any(t["unit_id"] == unit and t["access"] == "write" for t in cur_s.get("targets", []))
        findings.append(Finding("HIGH" if writes else "MEDIUM", "new_modbus_unit",
                                f"New Modbus unit ID {unit}",
                                f"{current.get('src')} -> {current.get('dst')} addressed unit {unit}, which was not observed for this communication in the baseline.",
                                {"unit_id": unit, "baseline_unit_ids": sorted(old_units)}))
    if "targets" not in old_s:
        return  # Legacy aggregate ranges cannot be assigned to a particular unit.
    seen = set()
    for target in cur_s.get("targets", []):
        # A new unit has its own finding. Keep target changes on known units.
        if target["unit_id"] not in old_units:
            continue
        matching = [t for t in old_s["targets"] if all(t[k] == target[k]
                    for k in ("unit_id", "address_space", "access"))]
        missing = _uncovered(target["start"], target["end"], matching)
        if not missing:
            continue
        identity = (target["unit_id"], target["address_space"], target["access"],
                    tuple((r["start"], r["end"]) for r in missing))
        if identity in seen:
            continue
        seen.add(identity)
        access = target["access"]
        label = ", ".join(f"{r['start']} to {r['end']}" if r["start"] != r["end"] else str(r["start"]) for r in missing)
        findings.append(Finding(
            "HIGH" if access == "write" else "MEDIUM", f"new_modbus_{access}_target",
            f"New Modbus {access} target on unit {target['unit_id']}",
            f"{current.get('src')} -> {current.get('dst')} used {access} access to {target['address_space']} addresses {label}, outside the ranges observed for this unit and access type in the baseline.",
            {"unit_id": target["unit_id"], "address_space": target["address_space"],
             "function_code": target["function_code"], "new_ranges": missing,
             "baseline_ranges": [{"start": t["start"], "end": t["end"]} for t in matching],
             "current": target.get("evidence", {}),
             "baseline": next((t.get("evidence", {}) for t in matching), old.get("evidence", {}))},
        ))


def _new_semantic_findings(findings: list[Finding], old: dict[str, Any], cur: dict[str, Any]) -> None:
    protocol = cur.get("protocol")
    old_s = old.get("semantics", {})
    cur_s = cur.get("semantics", {})
    src, dst = cur.get("src"), cur.get("dst")

    if protocol == "modbus":
        new_fc = set(cur_s.get("request_function_codes", cur_s.get("function_codes", []))) - set(
            old_s.get("request_function_codes", old_s.get("function_codes", [])))
        for fc in sorted(new_fc):
            sev = "CRITICAL" if fc in WRITE_FUNCTIONS else "HIGH" if fc == 90 else "MEDIUM"
            findings.append(Finding(sev, "new_modbus_function", f"New Modbus function code FC{fc}",
                                    f"{src} -> {dst} used Modbus function {fc}, which was not observed for this communication in the baseline.",
                                    {"src": src, "dst": dst, "function_code": fc}))
        if "write" in cur_s.get("access", []) and "write" not in old_s.get("access", []):
            findings.append(Finding("CRITICAL", "new_modbus_write", "Modbus write behaviour introduced",
                                    f"{src} -> {dst} performs Modbus writes; no writes were observed for this communication in the baseline.",
                                    {"write_ranges": cur_s.get("write_ranges", [])}))
        if 4 in cur_s.get("diagnostic_subfunctions", []) and 4 not in old_s.get("diagnostic_subfunctions", []):
            findings.append(Finding("CRITICAL", "modbus_listen_only", "Modbus Force Listen Only Mode observed",
                                    f"{src} -> {dst} sent FC8 diagnostic subfunction 4, which can silence a Modbus server.",
                                    {"function_code": 8, "diagnostic_subfunction": 4}))
        if 90 in new_fc:
            findings.append(Finding("HIGH", "modbus_umas", "Schneider UMAS engineering function introduced",
                                    "Modbus FC90 is associated with Schneider engineering operations; inspect the payload and endpoint roles.",
                                    {"function_code": 90}))

    elif protocol == "iec104":
        current_activations = set(cur_s.get("activations", []))
        old_activations = set(old_s.get("activations", old_s.get("type_ids", [])))
        for type_id in sorted(current_activations - old_activations):
            if type_id in CONTROL_TYPES:
                sev, kind, label = "CRITICAL", "new_iec104_command", "control command"
            elif type_id in RESET_TYPES:
                sev, kind, label = "CRITICAL", "new_iec104_reset_process", "reset process command"
            elif type_id in SYSTEM_TYPES:
                sev, kind, label = "LOW", "new_iec104_system_command", "system command"
            else:
                continue
            findings.append(Finding(sev, kind, f"New IEC-104 {label} ASDU {type_id}",
                                    f"{src} -> {dst} sent an activation (COT 6) for IEC-104 type {type_id}. "
                                    "Responses and activation confirmations are not treated as independent commands.",
                                    {"type_id": type_id, "cause_of_transmission": 6,
                                     "current": cur_s.get("activation_evidence", {}).get(str(type_id), {})}))
        new_types = set(cur_s.get("type_ids", [])) - set(old_s.get("type_ids", []))
        for type_id in sorted(new_types - current_activations):
            # A confirmation (COT 7/10) is not an issued command. Retain
            # visibility at INFO severity and never treat it as a control action.
            if type_id in CONTROL_TYPES | RESET_TYPES | SYSTEM_TYPES:
                findings.append(Finding("INFO", "new_iec104_type", f"IEC-104 type {type_id} observed without activation",
                                        "A new ASDU type was observed without a decoded activation in this direction; "
                                        "it may be a response or a partially captured exchange.",
                                        {"type_id": type_id}))
            else:
                findings.append(Finding("MEDIUM", "new_iec104_type", f"New IEC-104 ASDU type {type_id}",
                                        f"{src} -> {dst} used IEC-104 type {type_id}, not seen in the baseline.",
                                        {"type_id": type_id}))

    elif protocol == "dnp3":
        new_fc = set(cur_s.get("request_function_codes", [])) - set(old_s.get("request_function_codes", []))
        for fc in sorted(new_fc):
            sev = "CRITICAL" if fc in DNP3_RESTART or fc in {4, 5, 6} else "HIGH" if fc in DNP3_SENSITIVE else "MEDIUM"
            findings.append(Finding(sev, "new_dnp3_function", f"New DNP3 function {fc}",
                                    f"{src} -> {dst} introduced DNP3 application function {fc}; "
                                    "only CRC-valid single-fragment application messages are evaluated.",
                                    {"src": src, "dst": dst, "function_code": fc}))

    elif protocol == "s7comm":
        new_funcs = set(cur_s.get("functions", [])) - set(old_s.get("functions", []))
        for func in sorted(x for x in new_funcs if x is not None):
            sev = "CRITICAL" if func in WRITE_OR_ENGINEERING else "MEDIUM"
            findings.append(Finding(sev, "new_s7_function", f"New S7 function 0x{func:02x}",
                                    f"{src} -> {dst} used S7 function 0x{func:02x}, not seen in the baseline.",
                                    {"function": func}))
        if any(x in cur_s.get("access", []) for x in ("write", "engineering")) and not any(
            x in old_s.get("access", []) for x in ("write", "engineering")):
            findings.append(Finding("CRITICAL", "new_s7_change_operation", "S7 write/engineering behaviour introduced",
                                    f"{src} -> {dst} now contains S7 write or engineering operations absent from the baseline.", {}))
        new_groups = set(cur_s.get("userdata_groups", [])) - set(old_s.get("userdata_groups", []))
        if 4 in new_groups:
            findings.append(Finding("MEDIUM", "new_s7_cpu_userdata", "New S7 CPU Userdata activity",
                                    "S7 ROSCTR 7 CPU Userdata can include SZL reads and controller information requests; "
                                    "this is a partial decode, not a confirmed dangerous operation.",
                                    {"userdata_group": 4}))


def _modbus_value_findings(findings: list[Finding], old: dict, cur: dict) -> None:
    baseline = old.get("semantics", {}).get("write_value_ranges", {})
    observed = cur.get("semantics", {}).get("write_value_ranges", {})
    for register in sorted(set(baseline) & set(observed)):
        before, after = baseline[register], observed[register]
        if before.get("samples", 0) < 3:
            continue  # Too few samples to infer even a behavioural envelope.
        if after["min"] >= before["min"] and after["max"] <= before["max"]:
            continue
        findings.append(Finding("HIGH", "modbus_write_value_outlier", f"Modbus write outside observed values: {register}",
                                "A register/coil write exceeded the historical values in the baseline. "
                                "This is NOT a validated physical safety limit; confirm scaling and engineering constraints.",
                                {"register": register, "baseline": before, "current": after}))


def _rhythm_drift(findings: list[Finding], old: dict, cur: dict) -> None:
    baselines = {x["signature"]: x for x in old.get("semantics", {}).get("interval_profiles", [])}
    for now in cur.get("semantics", {}).get("interval_profiles", []):
        previous = baselines.get(now["signature"])
        if not previous or min(now.get("samples", 0), previous.get("samples", 0)) < 6:
            continue
        before, after = previous.get("median_seconds", 0), now.get("median_seconds", 0)
        if before <= 0 or after <= 0 or previous.get("mad_seconds", before) > before * 0.25:
            continue
        ratio = after / before
        if ratio <= 0.4 or ratio >= 2.5:
            findings.append(Finding("MEDIUM", "polling_rhythm_change", "Regular OT request interval changed",
                                    f"{cur.get('src')} -> {cur.get('dst')} kept an operation signature but "
                                    f"its median interval moved from {before:.3f}s to {after:.3f}s. "
                                    "Review capture windows and normal operating modes before concluding malicious replay.",
                                    {"signature": now["signature"], "baseline": previous, "current": now,
                                     "interval_ratio": round(ratio, 3)}))


def _link_iec104_confirmations(findings: list[Finding], conversations: dict[str, dict]) -> None:
    for finding in findings:
        if finding.kind not in {"new_iec104_command", "new_iec104_system_command", "new_iec104_reset_process"}:
            continue
        key = finding.evidence.get("conversation")
        conv = conversations.get(key, {})
        type_id = str(finding.evidence.get("type_id"))
        reverse_key = f"{conv.get('dst')}|{conv.get('src')}|{conv.get('transport')}|{conv.get('service_port')}|iec104"
        candidate_sem = conversations.get(reverse_key, {}).get("semantics", {})
        points = conv.get("semantics", {}).get("activation_points", {})
        replies = candidate_sem.get("confirmation_points", {})
        matched = next(((point, evidence, replies[point]) for point, evidence in points.items()
                        if point.startswith(type_id + ":") and point in replies), None)
        if matched:
            point, activation, confirmation = matched
            finding.evidence["activation_confirmation"] = confirmation
            finding.evidence["matched_point"] = point
            finding.evidence["confirmation_relationship"] = (
                "reverse direction; same type/common address/IOA; candidate correlation")
        elif not points and not replies:
            # Legacy capture analyses did not retain point-level matching keys.
            confirmation = candidate_sem.get("confirmation_evidence", {}).get(type_id)
            if confirmation:
                finding.evidence["activation_confirmation"] = confirmation
                finding.evidence["confirmation_relationship"] = (
                    "legacy reverse-direction type-only correlation; not transaction proof")



def _techniques_for(finding: Finding) -> list[dict[str, str]]:
    # Candidate ATT&CK for ICS mappings, not an assertion of attacker intent.
    mapping = {
        "new_modbus_write": [("T1692.001", "Unauthorized Message: Command Message"), ("T0836", "Modify Parameter")],
        "modbus_write_value_outlier": [("T0836", "Modify Parameter")],
        "new_iec104_command": [("T1692.001", "Unauthorized Message: Command Message")],
        "new_iec104_reset_process": [("T0816", "Device Restart/Shutdown")],
        "modbus_listen_only": [("T0804", "Block Reporting Message")],
        "modbus_umas": [("T0836", "Modify Parameter")],
        "new_s7_change_operation": [("T0843", "Program Download")],
        "new_s7_cpu_userdata": [("T0888", "Remote System Information Discovery")],
    }
    techniques = list(mapping.get(finding.kind, []))
    if finding.kind == "new_modbus_function":
        fc = finding.evidence.get("function_code")
        if fc in WRITE_FUNCTIONS:
            techniques = [("T0836", "Modify Parameter")]
        elif fc in {17, 43}:
            techniques = [("T0888", "Remote System Information Discovery")]
    if finding.kind == "new_s7_function":
        fc = finding.evidence.get("function")
        if fc in {0x1A, 0x1B, 0x1C}:
            techniques = [("T0843", "Program Download")]
        elif fc == 0x29:
            techniques = [("T0881", "Service Stop")]
    if finding.kind == "new_dnp3_function":
        fc = finding.evidence.get("function_code")
        if fc in {2, 3, 4, 5, 6}:
            techniques = [("T1692.001", "Unauthorized Message: Command Message")]
        elif fc in DNP3_RESTART:
            techniques = [("T0816", "Device Restart/Shutdown")]
    return [{"id": identifier, "name": name, "framework": "MITRE ATT&CK for ICS", "mapping": "candidate"}
            for identifier, name in techniques]


def _rate_drift(findings: list[Finding], old: dict[str, Any], cur: dict[str, Any],
                baseline_capture: dict | None = None, current_capture: dict | None = None) -> None:
    old_rate = old.get("packet_rate")
    cur_rate = cur.get("packet_rate")
    if old.get("packets", 0) < 10:
        return
    if cur.get("packets", 0) == 1:
        # A single packet has no conversation duration. Compare capture-wide
        # rates only if the observation windows are long enough and similar.
        base_duration = (baseline_capture or {}).get("duration_seconds") or 0
        current_duration = (current_capture or {}).get("duration_seconds") or 0
        if base_duration < 5 or not 0.8 <= current_duration / base_duration <= 1.25:
            return
        base_window_rate = old["packets"] / base_duration
        cur_window_rate = 1 / current_duration
        if cur_window_rate / base_window_rate <= 0.33:
            findings.append(Finding("HIGH" if cur.get("protocol") in OT_PROTOCOLS else "MEDIUM",
                                    "rate_decrease", "Communication nearly stopped (one packet observed)",
                                    f"{cur.get('src')} -> {cur.get('dst')} ({cur.get('protocol')}) "
                                    "had one packet in a capture of comparable duration to the baseline.",
                                    {"baseline_window_rate": base_window_rate,
                                     "current_window_rate": cur_window_rate, "current_packets": 1}))
        return
    if not old_rate or not cur_rate or cur.get("packets", 0) < 2:
        return
    envelope = old.get("packet_rate_range", {})
    high_ref = envelope.get("max") or old_rate
    low_ref = envelope.get("min") or old_rate
    ratio = cur_rate / old_rate
    if cur_rate >= 3.0 * high_ref:
        findings.append(Finding("MEDIUM", "rate_increase", f"Communication rate increased {ratio:.1f}x",
                                f"{cur.get('src')} -> {cur.get('dst')} ({cur.get('protocol')}) increased "
                                f"from {old_rate:.3f} to {cur_rate:.3f} packets/s.",
                                {"baseline_rate": old_rate, "current_rate": cur_rate, "ratio": ratio}))
    elif cur_rate <= 0.33 * low_ref:
        findings.append(Finding("HIGH" if cur.get("protocol") in OT_PROTOCOLS else "MEDIUM", "rate_decrease",
                                f"Communication rate fell to {ratio:.1%} of baseline",
                                f"{cur.get('src')} -> {cur.get('dst')} ({cur.get('protocol')}) decreased "
                                f"from {old_rate:.3f} to {cur_rate:.3f} packets/s; possible degraded polling or loss of view.",
                                {"baseline_rate": old_rate, "current_rate": cur_rate, "ratio": ratio}))

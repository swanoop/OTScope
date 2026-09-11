from __future__ import annotations

from typing import Any

from .models import Finding
from .protocols.iec104 import COMMAND_TYPES
from .protocols.modbus import WRITE_FUNCTIONS
from .protocols.s7 import WRITE_OR_ENGINEERING

OT_PROTOCOLS = {"modbus", "iec104", "s7comm", "dnp3", "ethernet-ip", "ethernet-ip-io", "opc-ua", "bacnet"}

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
        _rate_drift(findings, old, conv)
        _attach_evidence(findings[first_finding:], old, conv)

    for finding in findings:
        finding.evidence["baseline_capture_sha256"] = baseline.get("capture", {}).get("sha256")
        finding.evidence["current_capture_sha256"] = current.get("capture", {}).get("sha256")

    return [f.to_dict() for f in sorted(findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.title))]


def _attach_evidence(findings: list[Finding], old: dict, current: dict) -> None:
    for finding in findings:
        sample_key = {
            "new_modbus_write": "write", "new_iec104_command": "command",
            "new_s7_change_operation": "engineering",
        }.get(finding.kind)
        for field, prefix in (("function_code", "function"), ("function", "function"),
                              ("type_id", "type"), ("unit_id", "unit")):
            if field in finding.evidence:
                sample_key = f"{prefix}:{finding.evidence[field]}"
        samples = current.get("semantics", {}).get("operation_evidence", {})
        if finding.kind == "new_s7_change_operation" and sample_key not in samples:
            sample_key = "write"
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
        new_fc = set(cur_s.get("function_codes", [])) - set(old_s.get("function_codes", []))
        for fc in sorted(new_fc):
            sev = "CRITICAL" if fc in WRITE_FUNCTIONS else "MEDIUM"
            findings.append(Finding(sev, "new_modbus_function", f"New Modbus function code FC{fc}", f"{src} -> {dst} used Modbus function {fc}, which was not observed for this communication in the baseline.", {"src": src, "dst": dst, "function_code": fc}))
        if "write" in cur_s.get("access", []) and "write" not in old_s.get("access", []):
            findings.append(Finding("CRITICAL", "new_modbus_write", "Modbus write behaviour introduced", f"{src} -> {dst} performs Modbus writes; no writes were observed for this communication in the baseline.", {"write_ranges": cur_s.get("write_ranges", [])}))

    elif protocol == "iec104":
        new_types = set(cur_s.get("type_ids", [])) - set(old_s.get("type_ids", []))
        for type_id in sorted(new_types):
            sev = "CRITICAL" if type_id in COMMAND_TYPES else "MEDIUM"
            findings.append(Finding(sev, "new_iec104_type", f"New IEC-104 ASDU type {type_id}", f"{src} -> {dst} used IEC-104 type {type_id}, not seen in the baseline for this communication.", {"type_id": type_id}))
        if "command" in cur_s.get("access", []) and "command" not in old_s.get("access", []):
            findings.append(Finding("CRITICAL", "new_iec104_command", "IEC-104 command behaviour introduced", f"{src} -> {dst} now carries command-class ASDUs that were absent from the baseline.", {}))

    elif protocol == "s7comm":
        new_funcs = set(cur_s.get("functions", [])) - set(old_s.get("functions", []))
        for func in sorted(x for x in new_funcs if x is not None):
            sev = "CRITICAL" if func in WRITE_OR_ENGINEERING else "MEDIUM"
            findings.append(Finding(sev, "new_s7_function", f"New S7 function 0x{func:02x}", f"{src} -> {dst} used S7 function 0x{func:02x}, not seen in the baseline.", {"function": func}))
        if any(x in cur_s.get("access", []) for x in ("write", "engineering")) and not any(x in old_s.get("access", []) for x in ("write", "engineering")):
            findings.append(Finding("CRITICAL", "new_s7_change_operation", "S7 write/engineering behaviour introduced", f"{src} -> {dst} now contains S7 write or engineering operations absent from the baseline.", {}))


def _rate_drift(findings: list[Finding], old: dict[str, Any], cur: dict[str, Any]) -> None:
    old_rate = old.get("packet_rate")
    cur_rate = cur.get("packet_rate")
    if not old_rate or not cur_rate or old.get("packets", 0) < 10 or cur.get("packets", 0) < 10:
        return
    ratio = cur_rate / old_rate
    if ratio >= 3.0:
        findings.append(Finding("MEDIUM", "rate_increase", f"Communication rate increased {ratio:.1f}x", f"{cur.get('src')} -> {cur.get('dst')} ({cur.get('protocol')}) increased from {old_rate:.3f} to {cur_rate:.3f} packets/s.", {"baseline_rate": old_rate, "current_rate": cur_rate, "ratio": ratio}))

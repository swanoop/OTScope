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

    for key, conv in current_conv.items():
        old = base_conv.get(key)
        if old is None:
            sev = "HIGH" if conv.get("protocol") in OT_PROTOCOLS else "MEDIUM"
            findings.append(Finding(sev, "new_conversation", f"New {conv.get('protocol')} communication", f"{conv.get('src')} -> {conv.get('dst')} on service port {conv.get('service_port')} was not present in the baseline.", {"conversation": key}))
            _new_semantic_findings(findings, {}, conv)
            continue
        _new_semantic_findings(findings, old, conv)
        _rate_drift(findings, old, conv)

    return [f.to_dict() for f in sorted(findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.title))]


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

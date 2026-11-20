"""Merge independent capture analyses without inventing cross-capture traffic."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from statistics import median
from typing import Any


def _merge_semantics(target: dict, source: dict) -> None:
    union_lists = {
        "function_codes", "request_function_codes", "diagnostic_subfunctions",
        "unit_ids", "request_unit_ids", "access", "frame_types", "type_ids",
        "causes_of_transmission", "common_addresses", "activations", "confirmations",
        "rosctr", "functions", "userdata_groups", "userdata_subfunctions", "protocol_variants",
        "link_sources", "link_destinations", "decode_status", "device_identification",
        "read_ranges", "write_ranges",
    }
    for key in union_lists:
        if isinstance(source.get(key), list):
            combined = {str(x): x for x in target.get(key, [])}
            combined.update({str(x): x for x in source[key]})
            target[key] = sorted(combined.values(), key=lambda x: str(x))
    targets = target.setdefault("targets", [])
    for incoming in source.get("targets", []):
        signature = (incoming["unit_id"], incoming["address_space"], incoming["access"],
                     incoming["start"], incoming["end"], incoming["function_code"])
        if not any((x["unit_id"], x["address_space"], x["access"], x["start"],
                    x["end"], x["function_code"]) == signature for x in targets):
            targets.append(deepcopy(incoming))
    for key in ("operation_evidence", "activation_evidence", "confirmation_evidence",
                "activation_points", "confirmation_points"):
        dst = target.setdefault(key, {})
        for signature, evidence in source.get(key, {}).items():
            if signature not in dst or evidence.get("first_seen", float("inf")) < dst[signature].get("first_seen", float("inf")):
                dst[signature] = deepcopy(evidence)
    ranges = target.setdefault("write_value_ranges", {})
    for register, item in source.get("write_value_ranges", {}).items():
        if register not in ranges:
            ranges[register] = deepcopy(item)
        else:
            ranges[register]["min"] = min(ranges[register]["min"], item["min"])
            ranges[register]["max"] = max(ranges[register]["max"], item["max"])
            ranges[register]["samples"] += item["samples"]
    # Pool intervals only within their original captures. Never measure gaps
    # between separate PCAP files as polling intervals.
    by_sig = {p["signature"]: p for p in target.get("interval_profiles", [])}
    for profile in source.get("interval_profiles", []):
        old = by_sig.get(profile["signature"])
        if old is None:
            by_sig[profile["signature"]] = deepcopy(profile)
        else:
            values = (old.get("interval_sample_seconds", []) + profile.get("interval_sample_seconds", []))[:512]
            if values:
                center = median(values)
                old.update(median_seconds=round(center, 6),
                           mad_seconds=round(median([abs(v-center) for v in values]), 6),
                           samples=old.get("samples", 0) + profile.get("samples", 0),
                           interval_sample_seconds=values)
    if by_sig:
        target["interval_profiles"] = list(sorted(by_sig.values(), key=lambda x: x["signature"]))


def merge_baselines(analyses: list[dict[str, Any]]) -> dict[str, Any]:
    if len(analyses) < 2:
        raise ValueError("Provide at least two OTScope baseline JSON files to merge")
    for analysis in analyses:
        if analysis.get("tool") != "OTScope" or analysis.get("schema_version") not in (1, 2):
            raise ValueError("Every input must be a valid OTScope analysis")
    merged = deepcopy(analyses[0])
    merged["timeline"] = []
    merged["baseline_sources"] = []
    merged["coverage"]["warnings"] = []
    assets: dict[str, dict] = {}
    conversations: dict[str, dict] = {}
    for analysis in analyses:
        capture = analysis.get("capture", {})
        merged["baseline_sources"].append({"filename": capture.get("filename"), "sha256": capture.get("sha256"),
                                            "duration_seconds": capture.get("duration_seconds")})
        for warning in analysis.get("coverage", {}).get("warnings", []):
            if warning not in merged["coverage"]["warnings"]:
                merged["coverage"]["warnings"].append(warning)
        for a in analysis.get("assets", []):
            entry = assets.setdefault(a["ip"], {**deepcopy(a), "packets_tx": 0, "packets_rx": 0,
                                                 "bytes_tx": 0, "bytes_rx": 0})
            for key in ("packets_tx", "packets_rx", "bytes_tx", "bytes_rx"):
                entry[key] += a.get(key, 0)
            for key in ("protocols", "service_ports", "roles"):
                entry[key] = sorted(set(entry.get(key, [])) | set(a.get(key, [])))
        for c in analysis.get("conversations", []):
            key = c["key"]
            if key not in conversations:
                conversations[key] = deepcopy(c)
                conversations[key]["packet_rate_range"] = {"min": c.get("packet_rate"), "max": c.get("packet_rate")}
                continue
            target = conversations[key]
            for field in ("packets", "bytes"):
                target[field] = target.get(field, 0) + c.get(field, 0)
            start_values = [x for x in (target.get("first_seen"), c.get("first_seen")) if x is not None]
            end_values = [x for x in (target.get("last_seen"), c.get("last_seen")) if x is not None]
            target["first_seen"] = min(start_values) if start_values else None
            target["last_seen"] = max(end_values) if end_values else None
            rates = [x for x in (target["packet_rate_range"].get("min"), c.get("packet_rate")) if x is not None]
            if rates:
                target["packet_rate_range"]["min"] = min(rates)
            rates = [x for x in (target["packet_rate_range"].get("max"), c.get("packet_rate")) if x is not None]
            if rates:
                target["packet_rate_range"]["max"] = max(rates)
            _merge_semantics(target.setdefault("semantics", {}), c.get("semantics", {}))
    merged["assets"] = [assets[k] for k in sorted(assets)]
    merged["conversations"] = [conversations[k] for k in sorted(conversations)]
    merged["capture"] = {
        "filename": "merged-baseline", "sha256": sha256("|".join(
            str(item["sha256"]) for item in merged["baseline_sources"]).encode()).hexdigest(),
        "packets_total": sum(a.get("capture", {}).get("packets_total", 0) for a in analyses),
        "duration_seconds": sum(a.get("capture", {}).get("duration_seconds", 0) for a in analyses),
    }
    merged["coverage"]["warnings"].append(
        "Merged baseline spans independent captures. Rates use observed per-capture envelopes; no unobserved maintenance state is guaranteed.")
    return merged

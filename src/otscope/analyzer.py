from __future__ import annotations

import hashlib
import heapq
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .capture import decode_transport, read_capture
from . import __version__
from .models import Asset, Conversation, TimelineEvent
from .protocols import iec104, modbus, s7
from .reassembly import TCPReassembler

OT_PORTS = {
    ("tcp", 502): "modbus",
    ("tcp", 2404): "iec104",
    ("tcp", 102): "s7comm",
    ("tcp", 20000): "dnp3",
    ("tcp", 44818): "ethernet-ip",
    ("udp", 2222): "ethernet-ip-io",
    ("tcp", 4840): "opc-ua",
    ("udp", 47808): "bacnet",
}
KNOWN_PORTS = {
    ("tcp", 22): "ssh",
    ("tcp", 23): "telnet",
    ("tcp", 80): "http",
    ("tcp", 443): "https",
    ("tcp", 445): "smb",
    ("tcp", 3389): "rdp",
    ("tcp", 5900): "vnc",
    ("udp", 53): "dns",
    ("udp", 123): "ntp",
    ("udp", 161): "snmp",
    **OT_PORTS,
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _app_protocol(transport: str, sport: int, dport: int) -> tuple[str, int]:
    if (transport, dport) in KNOWN_PORTS:
        return KNOWN_PORTS[(transport, dport)], dport
    if (transport, sport) in KNOWN_PORTS:
        return KNOWN_PORTS[(transport, sport)], sport
    return transport, dport


def _role_for(protocol: str, destination_is_service: bool) -> str | None:
    if not destination_is_service:
        return None
    return {
        "modbus": "Modbus server candidate",
        "iec104": "IEC-104 controlled-station candidate",
        "s7comm": "S7 endpoint candidate",
        "dnp3": "DNP3 outstation candidate",
        "ethernet-ip": "EtherNet/IP endpoint candidate",
        "opc-ua": "OPC UA server candidate",
        "bacnet": "BACnet/IP endpoint candidate",
    }.get(protocol)


def analyze_capture(path: str | Path, timeline_limit: int | None = None) -> dict[str, Any]:
    if timeline_limit is not None and timeline_limit < 0:
        raise ValueError("timeline_limit must be non-negative or None")
    path = Path(path)
    capture_hash = _sha256(path)
    assets: dict[str, Asset] = {}
    conversations: dict[str, Conversation] = {}
    first_seen: float | None = None
    last_seen: float | None = None
    packet_count = 0
    decoded_count = 0
    timeline: list[tuple] = []
    event_count = 0
    coverage = Counter()
    protocols_decoded = Counter()
    reassembly = TCPReassembler()

    def add_event(event: TimelineEvent) -> None:
        nonlocal event_count
        event_count += 1
        item = (-event.timestamp, -event_count, event)
        if timeline_limit is None or len(timeline) < timeline_limit:
            heapq.heappush(timeline, item)
        elif timeline_limit and item > timeline[0]:
            heapq.heapreplace(timeline, item)

    def consume(messages) -> None:
        for message in messages:
            pkt, protocol = message.packet, message.protocol
            _, service_port = _app_protocol(pkt.transport, pkt.sport, pkt.dport)
            key = f"{pkt.src}|{pkt.dst}|{pkt.transport}|{service_port}|{protocol}"
            conv = conversations[key]
            parser = {"modbus": modbus, "iec104": iec104, "s7comm": s7}[protocol]
            sem = parser.parse(message.payload, request=pkt.dport == service_port)
            if not sem:
                coverage["messages_without_semantics"] += 1
                continue
            protocols_decoded[protocol] += 1
            evidence = message.evidence()
            evidence.update(capture_sha256=capture_hash, basis="decoded_message")
            {"modbus": _merge_modbus, "iec104": _merge_iec104, "s7comm": _merge_s7}[protocol](conv.semantics, sem)
            _remember_operation(conv.semantics, protocol, sem, evidence)
            if sem.get("request"):
                event = _semantic_event(evidence["first_seen"], pkt.src, pkt.dst, protocol, sem)
                if event:
                    event.evidence = evidence
                    add_event(event)

    for raw in read_capture(path):
        packet_count += 1
        first_seen = raw.timestamp if first_seen is None else min(first_seen, raw.timestamp)
        last_seen = raw.timestamp if last_seen is None else max(last_seen, raw.timestamp)
        pkt = decode_transport(raw)
        if len(raw.data) < raw.wire_len:
            coverage["truncated_packets"] += 1
        if pkt is None:
            coverage[raw.decode_issue or "non_tcp_udp_or_unsupported"] += 1
            continue
        decoded_count += 1
        protocol, service_port = _app_protocol(pkt.transport, pkt.sport, pkt.dport)
        dest_service = pkt.dport == service_port

        src_asset = assets.setdefault(pkt.src, Asset(pkt.src))
        dst_asset = assets.setdefault(pkt.dst, Asset(pkt.dst))
        src_asset.packets_tx += 1
        src_asset.bytes_tx += pkt.wire_len
        dst_asset.packets_rx += 1
        dst_asset.bytes_rx += pkt.wire_len
        src_asset.protocols.add(protocol)
        dst_asset.protocols.add(protocol)
        if dest_service and protocol != pkt.transport:
            dst_asset.service_ports.add(service_port)
            role = _role_for(protocol, True)
            if role:
                dst_asset.roles.add(role)

        key = f"{pkt.src}|{pkt.dst}|{pkt.transport}|{service_port}|{protocol}"
        conv = conversations.get(key)
        if conv is None:
            conv = Conversation(pkt.src, pkt.dst, pkt.transport, service_port, protocol)
            conv.evidence = {
                "frame_numbers": [pkt.frame_number], "first_seen": pkt.timestamp,
                "last_seen": pkt.timestamp, "interface_id": pkt.interface_id,
                "capture_sha256": capture_hash, "basis": "observed_transport",
                "wireshark_filter": f"frame.number == {pkt.frame_number}",
            }
            conversations[key] = conv
            add_event(TimelineEvent(
                pkt.timestamp, "INFO", "conversation", pkt.src, pkt.dst, protocol,
                f"First observed {protocol} conversation to service port {service_port}",
                {"service_port": service_port}, conv.evidence,
            ))
        conv.packets += 1
        conv.bytes += pkt.wire_len
        conv.first_seen = pkt.timestamp if conv.first_seen is None else min(conv.first_seen, pkt.timestamp)
        conv.last_seen = pkt.timestamp if conv.last_seen is None else max(conv.last_seen, pkt.timestamp)

        if protocol in {"modbus", "iec104", "s7comm"}:
            consume(reassembly.feed(pkt, protocol))

    consume(reassembly.finish())
    warnings = []
    if coverage["truncated_packets"]:
        warnings.append("Some packets were captured shorter than their wire length; missing bytes cannot be reconstructed.")
    if coverage["fragmented_ip"]:
        warnings.append("Fragmented IP packets were excluded from transport decoding; IP fragment reassembly is not supported.")
    if reassembly.stats["gap_events"] or reassembly.stats["incomplete_regions"]:
        warnings.append("TCP gaps or incomplete protocol messages were observed. Semantic coverage is incomplete.")
    if reassembly.stats["conflicting_overlap_streams"]:
        warnings.append("Conflicting TCP overlaps were observed. Affected buffered streams were excluded; any earlier findings from those streams require review.")
    if reassembly.stats["streams_evicted"] or reassembly.stats["late_unverified_bytes"]:
        warnings.append("TCP reconstruction limits were reached. Some stream context or late bytes could not be verified.")
    if reassembly.stats["unframed_bytes"] or coverage["messages_without_semantics"]:
        warnings.append("Some traffic on recognised OT ports could not be decoded as supported protocol operations.")
    if len(timeline) < event_count:
        warnings.append(f"Timeline limited to the earliest {len(timeline)} of {event_count} events. Re-run without --timeline-limit for a complete event export.")

    generated = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": 2,
        "tool": "OTScope",
        "tool_version": __version__,
        "generated_at": generated,
        "capture": {
            "path": str(path),
            "filename": path.name,
            "sha256": capture_hash,
            "packets_total": packet_count,
            "packets_decoded_tcp_udp": decoded_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "duration_seconds": (last_seen - first_seen) if first_seen is not None and last_seen is not None else 0.0,
        },
        "assets": [a.to_dict() for a in sorted(assets.values(), key=lambda x: x.ip)],
        "conversations": [c.to_dict() for c in sorted(conversations.values(), key=lambda x: x.key)],
        "timeline": [item[2].to_dict() for item in sorted(timeline, key=lambda x: (-x[0], -x[1]))],
        "coverage": {
            "packets_not_decoded_tcp_udp": packet_count - decoded_count,
            "truncated_packets": coverage["truncated_packets"],
            "fragmented_ip_packets": coverage["fragmented_ip"],
            "packet_decode_exclusions": {key: value for key, value in coverage.items()
                                          if key not in {"truncated_packets", "messages_without_semantics"}},
            "messages_without_semantics": coverage["messages_without_semantics"],
            "protocol_messages_decoded": dict(protocols_decoded),
            "tcp_reassembly": dict(reassembly.stats),
            "timeline": {"events_total": event_count, "events_retained": len(timeline),
                         "events_omitted": event_count-len(timeline), "limit": timeline_limit},
            "warnings": warnings,
        },
        "limitations": [
            "Passive analysis only; OTScope does not transmit packets to target systems.",
            "TCP reconstruction uses a 1 MiB per-direction capture window, at most 1024 active directions and 16 MiB of buffered payload. Missing capture bytes cannot be recovered.",
            "Messages are decoded within contiguous TCP regions. Midstream captures, late data beyond the reconstruction window, COTP segmentation and IP fragmentation can limit semantic coverage.",
            "Asset roles are evidence-based candidates inferred from observed service ports, not authoritative device identification.",
            "Encrypted application payloads cannot be semantically decoded.",
        ],
    }


def _set_add(container: dict[str, Any], key: str, value: Any) -> None:
    if value is None:
        return
    items = container.setdefault(key, [])
    if value not in items:
        items.append(value)
        try:
            items.sort()
        except TypeError:
            pass


def _range_add(container: dict[str, Any], key: str, start: Any, qty: Any) -> None:
    if start is None or qty is None:
        return
    item = {"start": int(start), "quantity": int(qty), "end": int(start) + int(qty) - 1}
    items = container.setdefault(key, [])
    if item not in items:
        items.append(item)
        items.sort(key=lambda x: (x["start"], x["quantity"]))


def _merge_modbus(dst: dict[str, Any], sem: dict[str, Any] | None) -> None:
    if not sem:
        return
    _set_add(dst, "function_codes", sem.get("function_code"))
    _set_add(dst, "unit_ids", sem.get("unit_id"))
    if sem.get("request"):
        _set_add(dst, "request_unit_ids", sem.get("unit_id"))
        _set_add(dst, "access", sem.get("access"))
        if sem.get("access") == "write":
            _range_add(dst, "write_ranges", sem.get("address_start"), sem.get("quantity"))
            _range_add(dst, "write_ranges", sem.get("write_address_start"), sem.get("write_quantity"))
        elif sem.get("access") == "read":
            _range_add(dst, "read_ranges", sem.get("address_start"), sem.get("quantity"))
        if sem.get("read_address_start") is not None:
            _range_add(dst, "read_ranges", sem.get("read_address_start"), sem.get("read_quantity"))


def _remember_operation(dst: dict[str, Any], protocol: str, sem: dict[str, Any], evidence: dict) -> None:
    samples = dst.setdefault("operation_evidence", {})
    names = []
    if protocol == "modbus":
        names.append(f"function:{sem['function_code']}")
    elif protocol == "iec104" and "type_id" in sem:
        names.append(f"type:{sem['type_id']}")
    elif protocol == "s7comm" and sem.get("function") is not None:
        names.append(f"function:{sem['function']}")
    if sem.get("request"):
        names.append(sem.get("access", "other"))
        if protocol == "modbus":
            names.append(f"unit:{sem['unit_id']}")
            fc = sem["function_code"]
            space = {1: "coil", 2: "discrete_input", 3: "holding_register", 4: "input_register",
                     5: "coil", 6: "holding_register", 15: "coil", 16: "holding_register",
                     22: "holding_register", 23: "holding_register"}.get(fc)
            targets = dst.setdefault("targets", [])
            for access, address, quantity in ((sem.get("access"), sem.get("address_start"), sem.get("quantity")),
                                               ("read", sem.get("read_address_start"), sem.get("read_quantity")),
                                               ("write", sem.get("write_address_start"), sem.get("write_quantity"))):
                if space and address is not None and quantity:
                    target = {"unit_id": sem["unit_id"], "address_space": space,
                              "access": access, "start": address, "end": address+quantity-1,
                              "function_code": fc}
                    existing = next((t for t in targets if all(t[k] == v for k, v in target.items())), None)
                    if existing is None:
                        targets.append({**target, "evidence": evidence})
                    elif evidence["first_seen"] < existing["evidence"]["first_seen"]:
                        existing["evidence"] = evidence
    for name in names:
        if name not in samples or evidence["first_seen"] < samples[name]["first_seen"]:
            samples[name] = evidence


def _merge_iec104(dst: dict[str, Any], sem: dict[str, Any] | None) -> None:
    if not sem:
        return
    _set_add(dst, "frame_types", sem.get("frame_type"))
    _set_add(dst, "type_ids", sem.get("type_id"))
    _set_add(dst, "causes_of_transmission", sem.get("cause_of_transmission"))
    _set_add(dst, "common_addresses", sem.get("common_address"))
    if sem.get("request"):
        _set_add(dst, "access", sem.get("access"))


def _merge_s7(dst: dict[str, Any], sem: dict[str, Any] | None) -> None:
    if not sem:
        return
    _set_add(dst, "rosctr", sem.get("rosctr"))
    _set_add(dst, "functions", sem.get("function"))
    if sem.get("request"):
        _set_add(dst, "access", sem.get("access"))


def _semantic_event(ts: float, src: str, dst: str, protocol: str, sem: dict[str, Any]) -> TimelineEvent | None:
    access = sem.get("access")
    if protocol == "modbus":
        fc = sem.get("function_code")
        name = sem.get("function_name", f"FC {fc}")
        severity = "HIGH" if access == "write" else "INFO"
        details = {k: sem[k] for k in ("function_code", "unit_id", "address_start", "quantity", "value") if k in sem}
        return TimelineEvent(ts, severity, "protocol_operation", src, dst, protocol, name, details)
    if protocol == "iec104" and sem.get("frame_type") == "I":
        severity = "HIGH" if access == "command" else "INFO"
        details = {k: sem[k] for k in ("type_id", "cause_of_transmission", "common_address", "information_object_address") if k in sem}
        return TimelineEvent(ts, severity, "protocol_operation", src, dst, protocol, sem.get("type_name", "IEC-104 I-frame"), details)
    if protocol == "s7comm" and sem.get("function") is not None:
        severity = "HIGH" if access in {"write", "engineering"} else "INFO"
        return TimelineEvent(ts, severity, "protocol_operation", src, dst, protocol, sem.get("function_name", "S7 operation"), {"function": sem.get("function"), "rosctr": sem.get("rosctr")})
    return None


def save_analysis(result: dict[str, Any], path: str | Path) -> None:
    Path(path).write_text(json.dumps(result, indent=2), encoding="utf-8")

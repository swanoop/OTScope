from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .capture import decode_transport, read_capture
from .models import Asset, Conversation, TimelineEvent
from .protocols import iec104, modbus, s7

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


def analyze_capture(path: str | Path, timeline_limit: int = 10_000) -> dict[str, Any]:
    path = Path(path)
    assets: dict[str, Asset] = {}
    conversations: dict[str, Conversation] = {}
    first_seen: float | None = None
    last_seen: float | None = None
    packet_count = 0
    decoded_count = 0
    timeline: list[TimelineEvent] = []

    for raw in read_capture(path):
        packet_count += 1
        first_seen = raw.timestamp if first_seen is None else min(first_seen, raw.timestamp)
        last_seen = raw.timestamp if last_seen is None else max(last_seen, raw.timestamp)
        pkt = decode_transport(raw)
        if pkt is None:
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
            conversations[key] = conv
            if len(timeline) < timeline_limit:
                timeline.append(TimelineEvent(
                    pkt.timestamp,
                    "INFO",
                    "conversation",
                    pkt.src,
                    pkt.dst,
                    protocol,
                    f"First observed {protocol} conversation to service port {service_port}",
                    {"service_port": service_port},
                ))
        conv.packets += 1
        conv.bytes += pkt.wire_len
        conv.first_seen = pkt.timestamp if conv.first_seen is None else min(conv.first_seen, pkt.timestamp)
        conv.last_seen = pkt.timestamp if conv.last_seen is None else max(conv.last_seen, pkt.timestamp)

        sem: dict[str, Any] | None = None
        if protocol == "modbus":
            sem = modbus.parse(pkt.payload, request=(pkt.dport == 502))
            _merge_modbus(conv.semantics, sem)
        elif protocol == "iec104":
            sem = iec104.parse(pkt.payload, request=(pkt.dport == 2404))
            _merge_iec104(conv.semantics, sem)
        elif protocol == "s7comm":
            sem = s7.parse(pkt.payload, request=(pkt.dport == 102))
            _merge_s7(conv.semantics, sem)

        if sem and sem.get("request") and len(timeline) < timeline_limit:
            event = _semantic_event(pkt.timestamp, pkt.src, pkt.dst, protocol, sem)
            if event:
                timeline.append(event)

    generated = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": 1,
        "tool": "OTScope",
        "tool_version": "0.1.0",
        "generated_at": generated,
        "capture": {
            "path": str(path),
            "filename": path.name,
            "sha256": _sha256(path),
            "packets_total": packet_count,
            "packets_decoded_tcp_udp": decoded_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "duration_seconds": (last_seen - first_seen) if first_seen is not None and last_seen is not None else 0.0,
        },
        "assets": [a.to_dict() for a in sorted(assets.values(), key=lambda x: x.ip)],
        "conversations": [c.to_dict() for c in sorted(conversations.values(), key=lambda x: x.key)],
        "timeline": [e.to_dict() for e in sorted(timeline, key=lambda x: x.timestamp)],
        "limitations": [
            "Passive analysis only; OTScope does not transmit packets to target systems.",
            "v0.1 does not perform TCP stream reassembly; protocol PDUs split across segments may not be decoded semantically.",
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
        _set_add(dst, "access", sem.get("access"))
        if sem.get("access") == "write":
            _range_add(dst, "write_ranges", sem.get("address_start"), sem.get("quantity"))
            _range_add(dst, "write_ranges", sem.get("write_address_start"), sem.get("write_quantity"))
        elif sem.get("access") == "read":
            _range_add(dst, "read_ranges", sem.get("address_start"), sem.get("quantity"))
        if sem.get("read_address_start") is not None:
            _range_add(dst, "read_ranges", sem.get("read_address_start"), sem.get("read_quantity"))


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

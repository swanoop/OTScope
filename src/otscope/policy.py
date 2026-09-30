"""Explicit, offline network policy checks against observed capture evidence."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
ADDRESS_SPACES = {"coil", "discrete_input", "holding_register", "input_register"}


class PolicyError(ValueError):
    pass


def _object(value, allowed, required, where):
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be an object")
    unknown, missing = set(value) - set(allowed), set(required) - set(value)
    if unknown or missing:
        raise PolicyError(f"{where}: unknown fields {sorted(unknown)}, missing fields {sorted(missing)}")


def _list(value, where, *, empty=False):
    if not isinstance(value, list) or (not value and not empty):
        raise PolicyError(f"{where} must be {'a' if empty else 'a non-empty'} list")
    return value


def _text(value, where):
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise PolicyError(f"{where} must be non-empty text of at most 200 characters")
    return value


def _identifier(value, where):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
        raise PolicyError(f"{where} must use 1 to 64 letters, digits, dots, underscores or hyphens")
    return value


def _integer(value, low, high, where):
    if type(value) is not int or not low <= value <= high:
        raise PolicyError(f"{where} must be an integer from {low} to {high}")
    return value


def _unique(values, where):
    if len(values) != len(set(values)):
        raise PolicyError(f"{where} contains duplicate entries")


def _numbers(value, low, high, where):
    values = _list(value, where)
    for item in values:
        _integer(item, low, high, where)
    _unique(values, where)


class NetworkPolicy:
    """A validated JSON policy; rule order is significant."""

    def __init__(self, document: dict[str, Any]):
        try:
            self._validate(document)
        except (TypeError, KeyError) as exc:
            raise PolicyError("Policy contains a field with an invalid type") from exc

    def _validate(self, document: dict[str, Any]):
        # Copy input so caller mutations cannot change a validated policy.
        self.document = json.loads(json.dumps(document))
        doc = self.document
        _object(doc, {"schema_version", "name", "default_action", "default_severity",
                      "zones", "assets", "conduits", "rules"},
                {"schema_version", "name", "default_action", "rules"}, "policy")
        if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
            raise PolicyError("policy.schema_version must be 1")
        self.name = _text(doc["name"], "policy.name")
        if doc["default_action"] not in ("deny", "observe"):
            raise PolicyError("default_action must be deny or observe")
        self.default_action = doc["default_action"]
        self.default_severity = doc.get("default_severity", "HIGH")
        if self.default_severity not in SEVERITIES:
            raise PolicyError("Invalid default_severity")
        self.zones, self.assets, self.assets_by_ip, self.conduits = {}, {}, {}, {}
        self.networks = []
        for zone in _list(doc.get("zones", []), "zones", empty=True):
            _object(zone, {"id", "name", "networks"}, {"id"}, "zone")
            key = _identifier(zone["id"], "zone.id")
            if key in self.zones:
                raise PolicyError(f"Duplicate zone: {key}")
            name = _text(zone.get("name", key), "zone.name")
            self.zones[key] = {"id": key, "name": name}
            for value in _list(zone.get("networks", []), "zone.networks", empty=True):
                if not isinstance(value, str):
                    raise PolicyError("Zone networks must be CIDR strings")
                try:
                    network = ipaddress.ip_network(value, strict=True)
                except ValueError as exc:
                    raise PolicyError(f"Invalid zone network: {value}") from exc
                if any(network.version == other.version and network.overlaps(other)
                       for other, _ in self.networks):
                    raise PolicyError(f"Overlapping zone networks: {value}")
                self.networks.append((network, key))
        for asset in _list(doc.get("assets", []), "assets", empty=True):
            _object(asset, {"id", "name", "ip", "zone"}, {"id", "ip"}, "asset")
            key = _identifier(asset["id"], "asset.id")
            if not isinstance(asset["ip"], str):
                raise PolicyError("asset.ip must be an IP address string")
            try:
                address = str(ipaddress.ip_address(asset["ip"]))
            except ValueError as exc:
                raise PolicyError(f"Invalid asset IP: {asset['ip']}") from exc
            zone = asset.get("zone")
            if zone is not None and zone not in self.zones:
                raise PolicyError(f"Unknown asset zone: {zone}")
            if key in self.assets or address in self.assets_by_ip:
                raise PolicyError("Asset IDs and IP addresses must be unique")
            entry = {"id": key, "ip": address, "name": _text(asset.get("name", key), "asset.name"), "zone": zone}
            self.assets[key] = entry
            self.assets_by_ip[address] = entry
        for conduit in _list(doc.get("conduits", []), "conduits", empty=True):
            _object(conduit, {"id", "name", "source_zone", "destination_zone"},
                    {"id", "source_zone", "destination_zone"}, "conduit")
            key = _identifier(conduit["id"], "conduit.id")
            if key in self.conduits:
                raise PolicyError(f"Duplicate conduit: {key}")
            for field in ("source_zone", "destination_zone"):
                if conduit[field] not in self.zones:
                    raise PolicyError(f"Unknown conduit zone: {conduit[field]}")
            if conduit["source_zone"] == conduit["destination_zone"]:
                raise PolicyError("A conduit must connect different configured zones")
            self.conduits[key] = {**conduit, "name": _text(conduit.get("name", key), "conduit.name")}
        self.rules = _list(doc["rules"], "rules", empty=True)
        ids = []
        for rule in self.rules:
            _object(rule, {"id", "source", "destination", "protocol", "transport", "service_port",
                           "action", "severity", "conduit", "modbus"},
                    {"id", "source", "destination", "protocol", "action"}, "rule")
            ids.append(_identifier(rule["id"], "rule.id"))
            self._validate_selector(rule["source"])
            self._validate_selector(rule["destination"])
            _text(rule["protocol"], "rule.protocol")
            if rule.get("transport", "*") not in ("*", "tcp", "udp"):
                raise PolicyError("rule.transport must be tcp, udp or *")
            if "service_port" in rule:
                _integer(rule["service_port"], 1, 65535, "rule.service_port")
            if rule["action"] not in ("allow", "deny"):
                raise PolicyError("rule.action must be allow or deny")
            if rule.get("severity", self.default_severity) not in SEVERITIES:
                raise PolicyError("Invalid rule severity")
            if "conduit" in rule and rule["conduit"] not in self.conduits:
                raise PolicyError(f"Unknown conduit: {rule['conduit']}")
            if "modbus" in rule:
                if rule["protocol"] != "modbus" or rule["action"] != "allow":
                    raise PolicyError("Modbus constraints require an allow rule with protocol modbus")
                self._validate_modbus(rule["modbus"])
        _unique(ids, "rule IDs")
        canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self.sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _validate_selector(self, selector):
        if not isinstance(selector, dict) or len(selector) != 1:
            raise PolicyError("An endpoint selector must have exactly one of asset, zone, network or any")
        kind, value = next(iter(selector.items()))
        if kind == "asset" and isinstance(value, str) and value in self.assets:
            return
        if kind == "zone" and isinstance(value, str) and value in self.zones:
            return
        if kind == "any" and value is True:
            return
        if kind == "network" and isinstance(value, str):
            try:
                ipaddress.ip_network(value, strict=True)
                return
            except ValueError:
                pass
        raise PolicyError(f"Invalid endpoint selector: {selector}")

    @staticmethod
    def _validate_modbus(constraints):
        _object(constraints, {"function_codes", "unit_ids", "access", "address_ranges"}, set(), "modbus")
        if not constraints:
            raise PolicyError("An empty modbus object does not define an operation constraint")
        if "function_codes" in constraints:
            _numbers(constraints["function_codes"], 1, 127, "modbus.function_codes")
        if "unit_ids" in constraints:
            _numbers(constraints["unit_ids"], 0, 255, "modbus.unit_ids")
        if "access" in constraints:
            values = _list(constraints["access"], "modbus.access")
            if any(value not in ("read", "write", "other") for value in values):
                raise PolicyError("modbus.access must contain read, write or other")
            _unique(values, "modbus.access")
        if "address_ranges" in constraints:
            for interval in _list(constraints["address_ranges"], "modbus.address_ranges"):
                _object(interval, {"space", "access", "start", "end"},
                        {"space", "access", "start", "end"}, "address range")
                if interval["space"] not in ADDRESS_SPACES or interval["access"] not in ("read", "write"):
                    raise PolicyError("Invalid address space or range access")
                _integer(interval["start"], 0, 65535, "range.start")
                _integer(interval["end"], interval["start"], 65535, "range.end")

    def resolve(self, address: str) -> dict:
        ip = ipaddress.ip_address(address)
        address = str(ip)
        asset = self.assets_by_ip.get(address, {})
        zone = asset.get("zone")
        if zone is None:
            zone = next((key for network, key in self.networks
                         if network.version == ip.version and ip in network), None)
        return {"ip": address, "asset_id": asset.get("id"), "name": asset.get("name", address),
                "zone_id": zone, "zone_name": self.zones[zone]["name"] if zone else "Unassigned"}

    def _matches(self, selector, endpoint):
        kind, value = next(iter(selector.items()))
        if kind == "any":
            return True
        if kind == "asset":
            return endpoint["asset_id"] == value
        if kind == "zone":
            return endpoint["zone_id"] == value
        network = ipaddress.ip_network(value)
        address = ipaddress.ip_address(endpoint["ip"])
        return network.version == address.version and address in network

    def match(self, conversation: dict):
        source, destination = self.resolve(conversation["src"]), self.resolve(conversation["dst"])
        for rule in self.rules:
            if not self._matches(rule["source"], source) or not self._matches(rule["destination"], destination):
                continue
            if rule["protocol"] not in ("*", conversation["protocol"]):
                continue
            if rule.get("transport", "*") not in ("*", conversation["transport"]):
                continue
            if "service_port" in rule and rule["service_port"] != conversation["service_port"]:
                continue
            if "conduit" in rule:
                conduit = self.conduits[rule["conduit"]]
                if (source["zone_id"], destination["zone_id"]) != (conduit["source_zone"], conduit["destination_zone"]):
                    continue
            return rule
        return None


def load_policy(path: str | Path) -> NetworkPolicy:
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PolicyError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    try:
        return NetworkPolicy(json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_keys))
    except (TypeError, KeyError) as exc:
        raise PolicyError("Policy contains a field with an invalid type") from exc


def modbus_targets(sem: dict) -> list[dict]:
    space = {1: "coil", 2: "discrete_input", 3: "holding_register", 4: "input_register",
             5: "coil", 6: "holding_register", 15: "coil", 16: "holding_register",
             22: "holding_register", 23: "holding_register"}.get(sem.get("function_code"))
    targets = []
    for access, start, quantity in ((sem.get("access"), sem.get("address_start"), sem.get("quantity")),
                                     ("read", sem.get("read_address_start"), sem.get("read_quantity")),
                                     ("write", sem.get("write_address_start"), sem.get("write_quantity"))):
        if space and start is not None and quantity:
            targets.append({"space": space, "access": access, "start": start, "end": start+quantity-1})
    return targets


def _covered(target, permitted):
    cursor = target["start"]
    relevant = sorted((r for r in permitted if r["space"] == target["space"] and r["access"] == target["access"]),
                      key=lambda r: (r["start"], r["end"]))
    for interval in relevant:
        if interval["end"] < cursor:
            continue
        if interval["start"] > cursor:
            return False
        cursor = max(cursor, interval["end"]+1)
        if cursor > target["end"]:
            return True
    return False


class PolicyEvaluator:
    """Collect policy evidence as messages are decoded, independent of timeline retention."""

    def __init__(self, policy: NetworkPolicy, capture_sha256: str):
        self.policy, self.capture_sha256 = policy, capture_sha256
        self.records: dict[str, dict] = {}
        self.findings: dict[tuple, dict] = {}

    def observe_flow(self, conversation: dict, packet) -> None:
        key = conversation["key"]
        source, destination = self.policy.resolve(conversation["src"]), self.policy.resolve(conversation["dst"])
        # Port classification identifies response directions only on recognised services.
        # This is not request/response transaction correlation.
        response = (conversation["protocol"] not in {"tcp", "udp"} and
                    packet.sport == conversation["service_port"] and packet.sport != packet.dport)
        rule = None if response else self.policy.match(conversation)
        action = "response" if response else rule["action"] if rule else self.policy.default_action
        status = {"response": "response_direction", "deny": "violation",
                  "observe": "unmatched", "allow": "flow_permitted"}[action]
        if rule and "modbus" in rule:
            status = "not_evaluated"
        self.records[key] = {"rule": rule, "source": source, "destination": destination,
                             "status": status, "requests_checked": 0, "unknown_operations": 0,
                             "violations": 0, "conduit_id": rule.get("conduit") if rule else None}
        if action == "deny":
            reason = f"Flow denied by rule {rule['id']}." if rule else "No allow rule matched this flow; the configured default is deny."
            self._record(key, "policy_flow_denied", reason, conversation.get("evidence", {}), None)

    def observe_undecoded(self, key: str) -> None:
        record = self.records[key]
        if record["rule"] and "modbus" in record["rule"]:
            record["unknown_operations"] += 1
            if record["status"] != "violation":
                record["status"] = "not_evaluated"

    def observe_message(self, key: str, sem: dict, evidence: dict) -> None:
        record = self.records[key]
        rule = record["rule"]
        if not sem.get("request") or not rule or rule["action"] != "allow" or "modbus" not in rule:
            return
        record["requests_checked"] += 1
        constraints, reasons = rule["modbus"], []
        targets = modbus_targets(sem)
        accesses = {target["access"] for target in targets} or {sem.get("access", "other")}
        if "function_codes" in constraints and sem["function_code"] not in constraints["function_codes"]:
            reasons.append(f"Function code {sem['function_code']} is outside the permitted set.")
        if "unit_ids" in constraints and sem["unit_id"] not in constraints["unit_ids"]:
            reasons.append(f"Unit ID {sem['unit_id']} is outside the permitted set.")
        if "access" in constraints and not accesses.issubset(constraints["access"]):
            reasons.append("The request includes an access type outside the permitted set.")
        unknown = False
        if "address_ranges" in constraints:
            if not targets:
                unknown = True
            elif any(not _covered(target, constraints["address_ranges"]) for target in targets):
                reasons.append("The request accesses addresses outside the permitted ranges for their address space and access type.")
        operation = {"function_code": sem["function_code"], "unit_id": sem["unit_id"],
                     "access": sorted(accesses), "targets": targets}
        if reasons:
            self._record(key, "policy_operation_denied", " ".join(reasons), evidence, operation)
            record["status"] = "violation"
        elif unknown:
            record["unknown_operations"] += 1
            if record["status"] != "violation":
                record["status"] = "not_evaluated"
        elif record["status"] != "violation" and not record["unknown_operations"]:
            record["status"] = "observed_operations_permitted"

    def _record(self, key, kind, reason, evidence, operation):
        record = self.records[key]
        rule = record["rule"]
        identity = (key, kind, json.dumps(operation, sort_keys=True))
        if identity not in self.findings:
            self.findings[identity] = {
                "severity": rule.get("severity", self.policy.default_severity) if rule else self.policy.default_severity,
                "kind": kind,
                "title": "Communication violates policy" if operation is None else "Modbus operation violates policy",
                "description": f"{record['source']['name']} -> {record['destination']['name']}: {reason}",
                "evidence": {"conversation": key, "rule_id": rule["id"] if rule else None,
                             "policy_sha256": self.policy.sha256, "current_capture_sha256": self.capture_sha256,
                             "current": dict(evidence), "operation": operation, "occurrences": 0},
            }
        finding = self.findings[identity]["evidence"]
        finding["occurrences"] += 1
        current = finding["current"]
        numbers = sorted(set(current.get("frame_numbers", [])) | set(evidence.get("frame_numbers", [])))
        current["frame_numbers"] = numbers[:20]
        current["frames_sample_limited"] = current.get("frames_sample_limited", False) or len(numbers) > 20
        if numbers:
            current["wireshark_filter"] = "frame.number in {" + " ".join(map(str, current["frame_numbers"])) + "}"
        current["first_seen"] = min(current.get("first_seen", evidence.get("first_seen", 0)), evidence.get("first_seen", 0))
        current["last_seen"] = max(current.get("last_seen", 0), evidence.get("last_seen", 0))
        record["violations"] += 1

    def finish(self, result: dict) -> None:
        for asset in result["assets"]:
            asset.update(self.policy.resolve(asset["ip"]))
        for conversation in result["conversations"]:
            record = self.records[conversation["key"]]
            conversation.update(source_name=record["source"]["name"], destination_name=record["destination"]["name"],
                                source_zone=record["source"]["zone_id"], destination_zone=record["destination"]["zone_id"])
            conversation["policy"] = {key: record[key] for key in
                                       ("status", "requests_checked", "unknown_operations", "violations", "conduit_id")}
            conversation["policy"]["rule_id"] = record["rule"]["id"] if record["rule"] else None
        counts = Counter(record["status"] for record in self.records.values())
        findings = sorted(self.findings.values(), key=lambda f: (f["evidence"]["conversation"], f["kind"], f["description"]))
        coverage = result.get("coverage", {})
        tcp = coverage.get("tcp_reassembly", {})
        restricted = any(r["rule"] and "modbus" in r["rule"] for r in self.records.values())
        # Reconstruction counters are capture-wide. Be conservative when a restricted
        # flow is present; do not attribute a gap to a particular flow without evidence.
        incomplete = bool(restricted and (
            coverage.get("truncated_packets") or coverage.get("fragmented_ip_packets") or
            coverage.get("messages_without_semantics") or any(tcp.get(name) for name in (
                "gap_events", "incomplete_regions", "conflicting_overlap_streams",
                "streams_evicted", "late_unverified_bytes", "unframed_bytes"))))
        result["policy"] = {
            "schema_version": 1, "name": self.policy.name, "sha256": self.policy.sha256,
            "default_action": self.policy.default_action, "zones": list(self.policy.zones.values()),
            "conduits": list(self.policy.conduits.values()), "findings": findings,
            "summary": {"flows_observed": len(self.records), "flows_with_violations": counts["violation"],
                        "flows_not_evaluated": counts["not_evaluated"], "unmatched_flows": counts["unmatched"],
                        "response_directions": counts["response_direction"], "findings": len(findings),
                        "requests_checked": sum(r["requests_checked"] for r in self.records.values()),
                        "semantic_coverage_incomplete": incomplete},
            "limitations": [
                "Rules are evaluated in order. The first flow match selects one rule; its operation constraints are then checked.",
                "Policy decisions describe observed traffic only. Missing or undecoded messages remain outside semantic assessment. Capture-wide decoding problems flag incomplete semantic coverage when restricted flows are present.",
                "Recognised service response directions are identified by port, not by transaction correlation or proof that a request was authorised.",
                "Configured zones and conduits are supplied by the analyst; the capture does not establish physical topology or standards compliance.",
            ],
        }

# Network policy reference

A policy supplies names, zone membership and rules for evaluating traffic observed in a capture. It is optional and works with both `analyze` and `compare`. It does not change baseline comparison results.

Use [examples/lab_policy.json](../examples/lab_policy.json) as a complete starting point:

```bash
otscope validate-policy examples/lab_policy.json
otscope analyze capture.pcap --policy examples/lab_policy.json -o report
otscope compare baseline.json capture.pcap --policy examples/lab_policy.json -o comparison
```

## Configuration

Policies are JSON objects. Unknown fields, duplicate JSON keys, invalid values, duplicate identifiers and overlapping zone networks are rejected before capture analysis.

| Field | Meaning |
| --- | --- |
| `schema_version` | Required integer `1` |
| `name` | Required display name |
| `default_action` | Required `deny` or `observe` for directions with no matching rule |
| `default_severity` | Optional finding severity; defaults to `HIGH` |
| `zones` | Optional list of `id`, optional `name`, and optional CIDR `networks` |
| `assets` | Optional list of `id`, `ip`, optional `name` and optional `zone` ID |
| `conduits` | Optional list of `id`, optional `name`, `source_zone` and `destination_zone` |
| `rules` | Required ordered list; an empty list applies the default to all assessed directions |

IDs use 1–64 letters, digits, dots, underscores or hyphens. Display names contain 1–200 characters. Asset IPs and IDs must be unique. IPv4 and IPv6 addresses and CIDRs are supported. CIDRs must be network addresses without host bits.

An asset's explicit zone overrides its CIDR membership. Other assets use the matching zone network; addresses outside configured networks remain unassigned. Zones may have no networks when assets are assigned explicitly. Overlapping zone CIDRs are rejected to avoid ambiguous membership.

Conduits name a permitted direction between two different zones. They do not allow traffic by themselves. A rule referencing a conduit can match only its configured source and destination zones.

## Flow rules

Every rule requires `id`, `source`, `destination`, `protocol` and `action`.

Each endpoint selector must contain exactly one of:

| Selector | Matches |
| --- | --- |
| `{"asset": "hmi"}` | A configured asset ID |
| `{"zone": "operations"}` | Any observed asset assigned to that zone |
| `{"network": "10.20.10.0/24"}` | An IP in the specified CIDR |
| `{"any": true}` | Any endpoint, including unassigned assets |

`protocol` matches OTScope's classifier name (for example `modbus`, `s7comm`, `iec104`, `https` or `tcp`), or `*` for any protocol. Optional `transport` is `tcp`, `udp` or `*`. Optional `service_port` is an integer from 1 to 65535. These selectors use the existing port classifier; they do not add decoding on non-standard ports.

`action` is `allow` or `deny`. Optional `severity` is `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO`. Optional `conduit` names a configured conduit.

The first matching flow rule is authoritative. Its operation constraints are checked afterward. A failed operation check does not fall through to a later rule. Combine permitted operations in one rule for the same flow or use distinct endpoint selectors.

On recognised service ports, directions originating from the service port are labelled `response_direction` and excluded from rule evaluation. This applies even to reply-only captures. It is a port heuristic, not transaction correlation, and those directions are never labelled permitted. Traffic on unknown ports uses the observed directional conversation as classified by OTScope.

## Modbus operation constraints

An allow rule with `protocol: "modbus"` can include a non-empty `modbus` object. All supplied constraints must pass for every decoded request:

| Constraint | Values |
| --- | --- |
| `function_codes` | Non-empty list of permitted integers 1–127 |
| `unit_ids` | Non-empty list of permitted integers 0–255 |
| `access` | Non-empty list containing `read`, `write` and/or `other` |
| `address_ranges` | Non-empty list of `space`, `access`, inclusive `start` and inclusive `end` |

Range spaces are `coil`, `discrete_input`, `holding_register` and `input_register`. Range access is `read` or `write`. Addresses are zero-based protocol addresses from 0 to 65535. Each target must fit the union of permitted ranges for its space and access type. FC23 checks both its read and write targets. Ranges apply to every unit permitted by that rule.

Unspecified constraints are unrestricted. An allow rule without `modbus` assesses only the flow. An undecoded target cannot establish range permission. Unsupported functions can still violate a decoded function, unit or access restriction, even if their targets are unavailable.

## Results and coverage

| Direction status | Meaning |
| --- | --- |
| `flow_permitted` | An allow rule matched without operation constraints |
| `observed_operations_permitted` | Decoded requests passed all supplied operation constraints |
| `violation` | The flow or at least one decoded request violated policy |
| `not_evaluated` | An operation-restricted flow had no assessable requests or had undecoded operations |
| `unmatched` | No rule matched and the default is observe |
| `response_direction` | Service response direction excluded from rule evaluation |

Capture-wide semantic decoding problems set `semantic_coverage_incomplete` when operation-restricted flows are present. This is conservative: reconstruction counters cannot reliably attribute every gap to a particular policy flow. Review coverage warnings even when some observed requests passed or no findings were produced.

Findings carry a SHA-256 of the parsed policy, a capture hash, rule ID, occurrence count and packet evidence. Policy object key order and JSON whitespace do not affect the hash; rule array order does. Repeated identical violations on one conversation are grouped, with up to 20 contributing frame references, explicit sample-limit metadata and the observed time interval.

Checks run during decoding, independently of timeline retention. They also run independently of baseline comparison: a prohibited operation already present in the baseline is still flagged.

`--fail-on-policy` requires `--policy`. It returns 1 after writing the report if there are policy findings, flows awaiting operation assessment, or incomplete semantic coverage. Otherwise it returns 0. Invalid input or configuration returns 2. Unmatched directions under an observe default and service response directions are outside this gate; exit 0 is not a completeness or compliance certificate.

The map initially displays at most 80 devices and 250 directions to keep the SVG usable. Its counts state when a view is limited. Filters work over the complete graph, and `topology.json` contains all observed nodes and edges. Map colours highlight findings and incomplete operation checks; they do not classify traffic as safe.

Configured zones and conduits express the analyst's model. The capture cannot establish physical topology, standards compliance, missing traffic, maintenance schedules or operating modes.

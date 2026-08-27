# OTScope roadmap

## v0.1: PCAP behavioural baseline

- PCAP and PCAPNG ingestion
- IPv4 and IPv6 TCP/UDP conversation model
- Modbus/TCP semantic extraction
- IEC 60870-5-104 semantic extraction
- S7comm identification and common job-function extraction
- Baseline JSON
- Baseline versus current comparison
- Protocol-aware timeline
- CSV, JSON, and static HTML reporting

## v0.2: Evidence quality

- TCP stream reassembly
- DNS and DHCP hostname enrichment
- MAC, OUI, and ARP asset evidence
- Modbus exception-response tracking
- IEC 60870-5-104 select-before-operate correlation
- S7 variable and address extraction
- Configurable severity and detection rules

## v0.3: Zone and conduit evidence

- User-defined zones
- Suggested communication groups
- Cross-zone flow matrix
- Least-privilege allow-list export
- Graphviz topology and flow diagrams

## v0.4: Additional OT protocols

- DNP3 semantics
- EtherNet/IP and CIP semantics
- OPC UA metadata
- BACnet/IP semantics
- IEC 61850 MMS and GOOSE research module

## v0.5: Incident evidence correlation

- Firewall CSV and syslog ingestion
- Windows event export and JSON ingestion
- PLC and engineering workstation log adapters
- Clock-normalised multi-source timeline
- MITRE ATT&CK for ICS mapping based on explicit evidence

## Design principles

OTScope remains passive by default. Observed evidence and inference must be kept separate. Inferred asset roles and security findings must not be presented as authoritative facts without operational context.

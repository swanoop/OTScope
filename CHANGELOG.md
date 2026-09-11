# Changelog

All notable changes to OTScope will be recorded here.

## 0.2.0

- Added bounded TCP reconstruction for split, coalesced, reordered and retransmitted OT messages
- Added Modbus unit and address-range change detection with separate address spaces and read/write access
- Added capture hashes, contributing frame numbers and Wireshark filters to operation and finding evidence
- Added capture coverage counters and warnings for incomplete, ambiguous or unsupported data
- Removed the implicit timeline limit; added an explicit CLI limit, complete selected-event exports and HTML pagination
- Added schema version 2 and an explicit compatibility notice for older baselines lacking detailed target evidence
- Corrected the synthetic Modbus payloads and TCP sequence numbers, and added regression coverage
- Simplified the README to document the current capabilities and operating limits

## 0.1.0

Initial public prototype.

- Added PCAP and PCAPNG parsing
- Added asset and conversation discovery
- Added Modbus/TCP semantic extraction
- Added IEC 60870-5-104 semantic extraction
- Added S7comm function extraction
- Added behavioural baseline generation
- Added baseline comparison and findings
- Added protocol event timeline
- Added JSON, CSV, and HTML reporting
- Added synthetic demonstration captures
- Added automated tests

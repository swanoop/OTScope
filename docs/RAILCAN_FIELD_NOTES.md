# Field notes: RailCAN + OTScope in an isolated rail lab

[RailCAN](https://github.com/swanoop/RailCAN) is a Classical CAN train-signal generator, scenario runner and end-to-end verifier. It can record CAN-native traffic, use SocketCAN and adapters, and transport its CAN messages using a documented CAN-over-IP framing format.

[OTScope](https://github.com/swanoop/OTScope) is a **different** tool: it parses Ethernet/IP PCAP and PCAPNG captures and decodes Modbus/TCP, IEC-104, DNP3 and S7 traffic as described in its coverage table. **OTScope does not decode native CAN frames or RailCAN's 13-byte CAN-over-IP payload format.** Do not present the two tools as one SCADA system.

## A repeatable cross-project experiment

1. Use RailCAN in an isolated simulator to generate a known-good train operating cycle. Record the CAN-side ground truth with RailCAN's capture/verify feature.
2. Add an **explicit laboratory gateway or digital-twin adapter** (not provided as an OTScope feature) that maps selected synthetic CAN values, such as speed or brake demand, to a Modbus/TCP holding-register view. Document the signal-to-register mapping; do not use this bridge on a live train.
3. Capture the Ethernet gateway's normal Modbus polling to `baseline.pcap` and create an OTScope baseline.
4. Repeat with a changed lab scenario: simulate a missing polling relationship, an altered polling interval or a new Modbus write in the **gateway-side IP capture**.
5. Compare the PCAPs using `otscope compare baseline.json changed.pcap -o report`. Verify whether the flow loss, write target or timing anomaly is reported and compare it with RailCAN's independent CAN-side measurements.

This experiment illustrates layered evidence: CAN emission and end-to-end fidelity from RailCAN, and IP-side network behaviour from OTScope. Neither tool alone proves process safety or a malicious compromise.

# Protocol coverage and interpretation

| Protocol | Implemented | Explicit limits |
| --- | --- | --- |
| Modbus/TCP | MBAP validation, FC1-6, 8, 15, 16, 17, 22, 23, 43/14 and 90 identification; request/read/write target ranges | FC90 is classified, not decoded at the vendor-engineering subfunction level; no register scaling or safe-range model |
| IEC 60870-5-104 | APCI I/S/U frames, ASDU type, common address, IOA, cause of transmission; activations COT 6 vs confirmations COT 7/10 | Confirmation matching uses reverse direction and type with evidence; it is a candidate association, not a transaction-level proof |
| DNP3 | Link frame length and all CRC blocks, complete one-fragment transport and application headers; function codes including 2–6, 13–14, 18, 25–30 | Segmented transport/application operations are **not** reassembled or semantically decoded. No object groups or secure-authentication negotiation analysis |
| S7comm | ROSCTR, function and partial Userdata group/subfunction, including CPU group (4) | No comprehensive SZL/object decoding or certified S7 mode classification |
| S7comm-Plus | Traffic recognised by 0x72 protocol ID | **Presence only; no application-command decode** |
| EtherNet/IP, OPC UA, BACnet | Service-port identification and directional flow modelling | No application layer decode |

## Interpretation rules

- A `missing_conversation` finding is emitted only when both source and destination IPs are observed in the new capture. It is a **loss-of-view hypothesis**, not an outage diagnosis. Capture vantage points and comparable operating periods are prerequisites for meaningful baselines.
- `rate_decrease` and `rate_increase` require a baseline with at least 10 packets and a current conversation with at least two packets. Large differences in capture windows can still distort findings.
- IEC-104 COT 6 control or reset activations are high-impact. A COT 7 or COT 10 reply alone will not generate a second critical command alert. General interrogation, test and clock-sync activations receive lower severity.
- DNP3 CRC rejection suppresses application classifications; transport/application segmentation is reported as undecoded. The tool never infers unobserved commands.
- Polling interval anomaly checks require at least six samples on each side and low baseline jitter. They are heuristic and are only as representative as the supplied capture periods.
- FC5/FC6 write values are retained as **raw protocol values** per unit/space/address. Exceeding a historical min or max does not mean an IEC 61508/61511 or process safety limit was exceeded. Thresholds should be validated against engineering data.
- MITRE ATT&CK for ICS IDs are **candidate techniques**; anomalous traffic is not proof of an attack. The current framework uses `T1692.001` (Command Message); older materials may refer to `T0855`.
- The offline HTML report displays candidate mappings. NDJSON and ECS-style NDJSON are intended for pipeline prototyping, not certified ECS conformance.

For full protocol decoders, consider Wireshark/tshark or protocol-specific tools and correlate with historian, engineering workstation and process-alarm evidence.

# Policy and zone example

This synthetic lab has an operator HMI, an engineering workstation, a historian and a PLC. The JSON policy gives each device a name and a zone. It allows the HMI and historian to read holding registers 0–99, and the engineering workstation to write registers 100–102, all on Modbus unit 1.

Generate the captures and validate the policy from the repository root:

```bash
python examples/generate_policy_demo.py policy-demo
otscope validate-policy examples/lab_policy.json
otscope analyze policy-demo/policy_baseline.pcap --policy examples/lab_policy.json -o policy-demo/normal-report
otscope analyze policy-demo/policy_changed.pcap --policy examples/lab_policy.json -o policy-demo/changed-report
```

Open `policy-demo/changed-report/report.html` in a browser. No server or internet connection is required. Filter the map by zone or device name, then select a conversation to inspect its matched rule, observed operations, and findings.

The baseline has three permitted requests and one service response direction. The changed capture produces exactly three policy findings:

| Frame | Observation | Policy finding |
| --- | --- | --- |
| 5 | Historian writes holding register 101 | Write access and function code 6 break its read-only rule |
| 6 | Engineering workstation writes registers 102–103 | Register 103 is outside the permitted range |
| 7 | Unconfigured 10.20.10.77 reads the PLC | No allow rule matches this source |

The response at frame 4 is labelled as a service response direction and excluded from rule evaluation. Port direction is not transaction correlation or proof of an authorised request.

The policy uses inclusive, zero-based protocol addresses. It permits engineering writes whenever this policy is supplied; it does not implement maintenance windows or infer an operating mode.

Policy evaluation also works alongside baseline comparison:

```bash
otscope baseline policy-demo/policy_baseline.pcap -o policy-demo/baseline.json
otscope compare policy-demo/baseline.json policy-demo/policy_changed.pcap --policy examples/lab_policy.json -o policy-demo/comparison
```

A prohibited operation remains a policy finding even if it already occurred in the baseline. To use the result in a script, add `--fail-on-policy`. The changed capture exits with status 1 after writing its report. Without that flag, completed analyses exit 0. Invalid configuration or input exits 2.

The policy, capture hash, frame references and rule IDs are retained in the JSON exports. The map shows IP conversations observed in these captures, not a physical wiring diagram.

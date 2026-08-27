# OTScope

Passive Industrial Network Behaviour and Security Profiler

![Tests](https://github.com/swanoop/OTScope/actions/workflows/tests.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

OTScope is a passive Python tool for analysing packet captures from industrial networks. It builds a model of observed assets and communications, extracts protocol-level activity, and compares later captures against a known-good baseline.

The current release supports PCAP and PCAPNG files, Modbus/TCP, IEC 60870-5-104, and common S7comm operations.

> OTScope is an early-stage defensive assessment tool. Findings identify behaviour worth investigating. They do not prove malicious activity.

## Project background

OTScope started as part of an OT home lab used to generate and inspect packet captures from simulated industrial traffic. The initial goal was practical: take PCAP files from the lab, identify which systems were communicating, inspect the protocol operations being used, and compare normal traffic with changed behaviour without actively probing the devices.

The project is being developed as a defensive analysis tool for repeatable lab testing, protocol study, assessment work, and incident investigation.

## Features

- Parse PCAP and PCAPNG captures directly in Python
- Build an observed asset inventory
- Build a directional communication matrix
- Identify common OT and supporting network services
- Extract Modbus/TCP function codes, unit IDs, access type, and register ranges
- Extract IEC 60870-5-104 frame and ASDU information
- Identify common S7comm read, write, upload, download, and PLC control functions
- Save a capture as a reusable behavioural baseline
- Compare current traffic with a baseline
- Flag new assets, conversations, write operations, commands, and major rate changes
- Produce a protocol-aware event timeline
- Export JSON, CSV, and a standalone HTML report

OTScope performs file analysis only. It does not transmit traffic to the systems being assessed.

## Why OTScope

A normal flow list can show that two hosts communicated over TCP/502. For an OT assessment, that is often not enough. The useful question is what the protocol was doing.

A baseline might contain:

```text
10.0.0.10 -> 10.0.0.20
Protocol: Modbus/TCP
Observed operation: FC03 Read Holding Registers
Observed range: 0 to 23
Write operations observed: no
```

A later capture may contain:

```text
CRITICAL  Modbus write behaviour introduced
10.0.0.10 -> 10.0.0.20
Observed operation: FC16 Write Multiple Registers
Observed range: 100 to 102
```

OTScope records that change as evidence for investigation rather than declaring it an attack.

## Architecture

```text
PCAP / PCAPNG
      |
      v
Capture parser
      |
      v
Ethernet / IP / TCP / UDP
      |
      v
Protocol classification
      |
      +---- Modbus/TCP
      +---- IEC 60870-5-104
      +---- S7comm
      |
      v
Behaviour model
      |
      +---- assets
      +---- conversations
      +---- protocol semantics
      +---- timeline events
      |
      +-------------------+
      |                   |
      v                   v
baseline.json          reports
      |
      v
Current capture
      |
      v
Behaviour comparison
      |
      v
Security findings
```

## Installation

Python 3.10 or later is required. OTScope v0.1 has no third-party runtime dependencies.

```bash
git clone https://github.com/swanoop/OTScope.git
cd OTScope
python -m venv .venv
```

Linux or macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install the command line tool:

```bash
pip install -e .
```

## Quick start

Generate the demonstration captures:

```bash
python examples/generate_demo_pcaps.py
```

Analyse a capture:

```bash
otscope analyze examples/baseline_demo.pcap -o otscope-report
```

Create a baseline:

```bash
otscope baseline examples/baseline_demo.pcap -o baseline.json
```

Compare a second capture with the baseline:

```bash
otscope compare baseline.json examples/changed_demo.pcap -o otscope-comparison
```

Extract the protocol timeline:

```bash
otscope timeline examples/changed_demo.pcap -o timeline.json
```

## Output

A comparison report contains:

```text
otscope-comparison/
|-- analysis.json
|-- findings.json
|-- communication_matrix.csv
|-- timeline.csv
`-- report.html
```

Example finding types:

| Severity | Finding |
| --- | --- |
| CRITICAL | Modbus write behaviour not present in the baseline |
| CRITICAL | New IEC 60870-5-104 command-class ASDU |
| CRITICAL | New S7comm write or engineering operation |
| HIGH | New OT protocol communication relationship |
| MEDIUM | New asset |
| MEDIUM | New non-write protocol operation |
| MEDIUM | Communication rate at least 3 times the baseline |
| INFO | Baseline asset not observed in the current capture |

Severity represents investigation priority only.

## Protocol coverage

### Modbus/TCP

OTScope currently handles common read and write requests including FC01, FC02, FC03, FC04, FC05, FC06, FC15, FC16, FC22, and FC23. Where the request format allows it, the tool records the affected coil or register range.

### IEC 60870-5-104

OTScope identifies I, S, and U frames. For I-frames it extracts the ASDU type, cause of transmission, common address, and first information object address. Command-class ASDUs are tracked separately from telemetry during baseline comparison.

### S7comm

OTScope recognises the S7comm header and common job functions including Read Var, Write Var, upload and download operations, PI Service, and PLC Stop. Detailed S7 variable and address decoding is planned for a later release.

## Behavioural comparison

Conversation comparison uses a directional key based on:

```text
source IP | destination IP | transport | service port | protocol
```

Ephemeral client ports are not part of the comparison key. This reduces false differences caused by normal TCP source port changes.

The baseline represents observed traffic, not a complete definition of acceptable plant behaviour. A short capture may not include startup, maintenance, degraded mode, or rare safety-related operations.

## Current limitations

- TCP stream reassembly is not implemented yet
- Protocol identification is primarily based on known service ports
- Non-standard protocol ports require future configuration support
- Asset roles are inferred candidates, not authoritative labels
- A baseline can only represent the conditions captured
- High-severity findings still require engineering and operational context

## Development

Install pytest and run the test suite:

```bash
pip install -e . pytest
pytest -q
```

The repository includes synthetic demonstration PCAPs so protocol parsing and comparison can be tested without using production network captures.

## Project structure

```text
src/otscope/        core package
src/otscope/protocols/ protocol parsers
tests/              parser and comparison tests
examples/           synthetic capture generator and sample PCAPs
docs/               architecture notes and roadmap
.github/workflows/  automated tests
```

## Roadmap

Planned work includes TCP stream reassembly, better asset evidence, deeper S7 decoding, IEC 60870-5-104 select-before-operate correlation, zone and conduit analysis, additional OT protocols, and multi-source incident timeline correlation.

See [docs/ROADMAP.md](docs/ROADMAP.md) for the current development plan.

## Responsible use

Use OTScope only with packet captures that you are authorised to inspect. The project is intended for defensive OT security assessment, engineering analysis, and incident response.

## Licence

MIT License. See [LICENSE](LICENSE).

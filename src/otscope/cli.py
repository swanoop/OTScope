from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze_capture, save_analysis
from .compare import compare
from .report import write_outputs


def _load(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("tool") != "OTScope" or data.get("schema_version") not in (1, 2):
        raise ValueError("Expected an OTScope baseline with schema version 1 or 2")
    if not isinstance(data.get("assets"), list) or not isinstance(data.get("conversations"), list):
        raise ValueError("Baseline is missing its asset or conversation lists")
    return data


def _summary(result: dict) -> str:
    return (
        f"packets={result['capture']['packets_total']} "
        f"assets={len(result['assets'])} "
        f"conversations={len(result['conversations'])} "
        f"timeline_events={len(result['timeline'])}"
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="otscope", description="Passive industrial network behaviour and security profiler")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analyse a PCAP/PCAPNG and write JSON/CSV/HTML output")
    a.add_argument("capture")
    a.add_argument("-o", "--out", default="otscope-report")

    b = sub.add_parser("baseline", help="Create a reusable baseline JSON from a known-good capture")
    b.add_argument("capture")
    b.add_argument("-o", "--out", default="baseline.json")

    c = sub.add_parser("compare", help="Compare a capture with a baseline and generate findings")
    c.add_argument("baseline")
    c.add_argument("capture")
    c.add_argument("-o", "--out", default="otscope-comparison")

    t = sub.add_parser("timeline", help="Extract protocol-aware timeline events as JSON")
    t.add_argument("capture")
    t.add_argument("-o", "--out", default="timeline.json")
    for command in (a, b, c, t):
        command.add_argument("--timeline-limit", type=int, default=None, metavar="N",
                             help="Retain the earliest N events; default exports every decoded event")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "analyze":
            result = analyze_capture(args.capture, timeline_limit=args.timeline_limit)
            report = write_outputs(result, args.out)
            print(f"Analysed {args.capture}: {_summary(result)}")
            print(f"Report: {report}")
        elif args.command == "baseline":
            result = analyze_capture(args.capture, timeline_limit=args.timeline_limit)
            save_analysis(result, args.out)
            print(f"Baseline created: {args.out} ({_summary(result)})")
        elif args.command == "compare":
            baseline = _load(args.baseline)
            current = analyze_capture(args.capture, timeline_limit=args.timeline_limit)
            result = current
            findings = compare(baseline, current)
            report = write_outputs(current, args.out, findings=findings)
            critical = sum(1 for x in findings if x["severity"] == "CRITICAL")
            high = sum(1 for x in findings if x["severity"] == "HIGH")
            print(f"Comparison complete: findings={len(findings)} critical={critical} high={high}")
            print(f"Report: {report}")
        elif args.command == "timeline":
            result = analyze_capture(args.capture, timeline_limit=args.timeline_limit)
            Path(args.out).write_text(json.dumps(result["timeline"], indent=2), encoding="utf-8")
            metadata = Path(args.out).with_suffix(".metadata.json")
            metadata.write_text(json.dumps({key: result[key] for key in ("tool", "tool_version", "schema_version", "capture", "coverage")}, indent=2), encoding="utf-8")
            print(f"Timeline written: {args.out} ({len(result['timeline'])} events)")
            print(f"Capture and coverage metadata: {metadata}")
        for warning in result.get("coverage", {}).get("warnings", []):
            print(f"warning: {warning}", file=sys.stderr)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

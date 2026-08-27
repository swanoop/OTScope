from pathlib import Path
import runpy

from otscope.analyzer import analyze_capture
from otscope.compare import compare


def test_demo_end_to_end(tmp_path):
    module = runpy.run_path(str(Path(__file__).parents[1] / "examples" / "generate_demo_pcaps.py"))
    # Use generator helpers with temporary paths rather than polluting source tree.
    base = [module["tcp_frame"]("10.0.0.10", "10.0.0.20", 40000, 502, module["modbus_req"](3, 0, 10, 1))]
    changed = base + [module["tcp_frame"]("10.0.0.10", "10.0.0.20", 40000, 502, module["modbus_req"](16, 100, 3, 2))]
    bp = tmp_path / "base.pcap"
    cp = tmp_path / "changed.pcap"
    module["write_pcap"](bp, base)
    module["write_pcap"](cp, changed)
    baseline = analyze_capture(bp)
    current = analyze_capture(cp)
    findings = compare(baseline, current)
    assert len(baseline["assets"]) == 2
    assert any(f["kind"] == "new_modbus_write" for f in findings)

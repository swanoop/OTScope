from __future__ import annotations

import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__


def _ts(value: float | None) -> str:
    if value is None:
        return ""
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def write_outputs(result: dict[str, Any], out_dir: str | Path, findings: list[dict[str, Any]] | None = None) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "analysis.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    if findings is not None:
        (out / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    _write_matrix(result, out / "communication_matrix.csv")
    _write_timeline(result, out / "timeline.csv")
    html_path = out / "report.html"
    html_path.write_text(_html_report(result, findings), encoding="utf-8")
    return html_path


def _write_matrix(result: dict[str, Any], path: Path) -> None:
    fields = ["src", "dst", "transport", "service_port", "protocol", "packets", "bytes", "first_seen", "last_seen", "semantics"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for c in result.get("conversations", []):
            w.writerow({
                "src": c.get("src"), "dst": c.get("dst"), "transport": c.get("transport"),
                "service_port": c.get("service_port"), "protocol": c.get("protocol"),
                "packets": c.get("packets"), "bytes": c.get("bytes"),
                "first_seen": _ts(c.get("first_seen")), "last_seen": _ts(c.get("last_seen")),
                "semantics": json.dumps(c.get("semantics", {}), separators=(",", ":")),
            })


def _write_timeline(result: dict[str, Any], path: Path) -> None:
    fields = ["timestamp", "severity", "category", "src", "dst", "protocol", "summary", "details", "evidence"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for e in result.get("timeline", []):
            row = dict(e)
            row["timestamp"] = _ts(e.get("timestamp"))
            row["details"] = json.dumps(e.get("details", {}), separators=(",", ":"))
            row["evidence"] = json.dumps(e.get("evidence", {}), separators=(",", ":"))
            w.writerow(row)


def _html_report(result: dict[str, Any], findings: list[dict[str, Any]] | None) -> str:
    cap = result.get("capture", {})
    compared = findings is not None
    findings = findings or []
    coverage = result.get("coverage", {})
    timeline_coverage = coverage.get("timeline", {})
    warning_rows = "".join(f"<li>{html.escape(w)}</li>" for w in coverage.get("warnings", []))
    coverage_notice = f"<ul class='notice'>{warning_rows}</ul>" if warning_rows else "<p>No coverage warnings were recorded. This does not establish that the capture covers every operating condition.</p>"
    sev_counts = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    for f in findings:
        sev_counts[f.get("severity", "INFO")] = sev_counts.get(f.get("severity", "INFO"), 0) + 1

    finding_rows = "".join(
        f"<tr><td><span class='sev {html.escape(f.get('severity','INFO').lower())}'>{html.escape(f.get('severity',''))}</span></td>"
        f"<td>{html.escape(f.get('title',''))}</td><td>{html.escape(f.get('description',''))}</td>"
        f"<td><details><summary>View evidence</summary><pre>{html.escape(json.dumps(f.get('evidence',{}), indent=2))}</pre></details></td></tr>"
        for f in findings
    ) or ("<tr><td colspan='4'>Comparison completed with no detected baseline differences. Review capture coverage below.</td></tr>" if compared else "<tr><td colspan='4'>No baseline comparison was performed.</td></tr>")

    asset_rows = "".join(
        f"<tr><td>{html.escape(a['ip'])}</td><td>{html.escape(', '.join(a.get('protocols', [])))}</td>"
        f"<td>{html.escape(', '.join(a.get('roles', [])))}</td><td>{a.get('packets_tx',0)}</td><td>{a.get('packets_rx',0)}</td></tr>"
        for a in result.get("assets", [])
    )
    conv_rows = "".join(
        f"<tr><td>{html.escape(c['src'])}</td><td>{html.escape(c['dst'])}</td><td>{html.escape(c['protocol'])}</td>"
        f"<td>{c.get('service_port')}</td><td>{c.get('packets')}</td><td><details><summary>Protocol activity</summary><code>{html.escape(json.dumps({k: v for k, v in c.get('semantics', {}).items() if k not in {'operation_evidence', 'targets'}}, separators=(',', ':')))}</code></details></td></tr>"
        for c in result.get("conversations", [])
    )
    timeline_rows = "".join(
        f"<tr><td>{html.escape(_ts(e.get('timestamp')))}</td><td>{html.escape(e.get('severity',''))}</td>"
        f"<td>{html.escape(e.get('src',''))} -> {html.escape(e.get('dst',''))}</td><td>{html.escape(e.get('protocol',''))}</td><td>{html.escape(e.get('summary',''))}</td>"
        f"<td><code>{html.escape(e.get('evidence',{}).get('wireshark_filter',''))}</code></td></tr>"
        for e in result.get("timeline", [])
    )

    return f"""<!doctype html>
<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>OTScope Report</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f5f7f9;color:#17202a}}main{{max-width:1400px;margin:auto;padding:28px}}
h1{{margin-bottom:4px}}.muted{{color:#64748b}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}}.card{{background:white;border:1px solid #dde3e8;border-radius:10px;padding:16px}}
table{{width:100%;border-collapse:collapse;background:white;margin:12px 0 28px}}th,td{{border-bottom:1px solid #e6eaee;padding:9px;text-align:left;vertical-align:top}}th{{background:#eef2f5;position:sticky;top:0}}code{{font-size:11px;white-space:pre-wrap;word-break:break-word}}
.sev{{font-weight:700}}.critical{{color:#8b0000}}.high{{color:#b45309}}.medium{{color:#8a6d00}}.low{{color:#2563eb}}.info{{color:#475569}}.scroll{{overflow:auto;max-height:650px;border:1px solid #dde3e8}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;max-width:600px}}.notice{{background:#fff4d6;padding:16px 32px;border:1px solid #e0bc59}}button{{padding:7px 14px;margin:5px}}[hidden]{{display:none!important}}
</style></head><body><main>
<h1>OTScope</h1><div class='muted'>Passive Industrial Network Behaviour & Security Profiler | v{html.escape(__version__)}</div>
<div class='cards'>
<div class='card'><b>Capture</b><br>{html.escape(cap.get('filename',''))}</div>
<div class='card'><b>Packets</b><br>{cap.get('packets_total',0)}</div>
<div class='card'><b>Assets</b><br>{len(result.get('assets',[]))}</div>
<div class='card'><b>Conversations</b><br>{len(result.get('conversations',[]))}</div>
<div class='card'><b>Critical</b><br>{sev_counts.get('CRITICAL',0)}</div>
<div class='card'><b>High</b><br>{sev_counts.get('HIGH',0)}</div>
</div>
<h2>Capture coverage</h2>
<p>Capture SHA-256: <code>{html.escape(cap.get('sha256',''))}</code><br>
Capture interval (UTC): {html.escape(_ts(cap.get('first_seen')))} to {html.escape(_ts(cap.get('last_seen')))}<br>
TCP/UDP packets decoded: {cap.get('packets_decoded_tcp_udp',0)} of {cap.get('packets_total',0)}.<br>
Timeline events retained: {timeline_coverage.get('events_retained',len(result.get('timeline',[])))} of {timeline_coverage.get('events_total',len(result.get('timeline',[])))}; omitted: {timeline_coverage.get('events_omitted',0)}.</p>
{coverage_notice}
<details><summary>Decoding and reconstruction counts</summary><pre>{html.escape(json.dumps(coverage, indent=2))}</pre></details>
<h2>Comparison findings</h2><div class='scroll'><table><thead><tr><th>Severity</th><th>Finding</th><th>Description</th><th>Evidence</th></tr></thead><tbody>{finding_rows}</tbody></table></div>
<h2>Assets</h2><div class='scroll'><table><thead><tr><th>IP</th><th>Protocols</th><th>Inferred roles</th><th>TX packets</th><th>RX packets</th></tr></thead><tbody>{asset_rows}</tbody></table></div>
<h2>Communication matrix</h2><div class='scroll'><table><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Port</th><th>Packets</th><th>Semantics</th></tr></thead><tbody>{conv_rows}</tbody></table></div>
<h2>Protocol timeline</h2><p>All retained events are included in this report and in <a href='timeline.csv'>timeline.csv</a>. Capture and evidence metadata are in <a href='analysis.json'>analysis.json</a>.</p>
<nav id='timeline-pages' aria-label='Timeline pages' hidden><button type='button' id='previous'>Previous</button><span id='page-status' aria-live='polite'></span><button type='button' id='next'>Next</button></nav>
<div class='scroll'><table><thead><tr><th>Time (UTC)</th><th>Severity</th><th>Flow</th><th>Protocol</th><th>Event</th><th>Wireshark filter</th></tr></thead><tbody id='timeline-rows'>{timeline_rows}</tbody></table></div>
<h2>Limitations</h2><ul>{''.join(f'<li>{html.escape(x)}</li>' for x in result.get('limitations',[]))}</ul>
</main><script>
(() => {{
const rows=Array.from(document.querySelectorAll('#timeline-rows tr'));
const size=100; let page=0; const pages=Math.ceil(rows.length/size);
if(pages<=1)return;
document.getElementById('timeline-pages').hidden=false;
const show=()=>{{rows.forEach((row,i)=>row.hidden=i<page*size||i>=(page+1)*size);
document.getElementById('page-status').textContent=`Page ${{page+1}} of ${{pages}} (${{rows.length}} events)`;
document.getElementById('previous').disabled=page===0;document.getElementById('next').disabled=page===pages-1;}};
document.getElementById('previous').onclick=()=>{{if(page>0)page--;show();}};
document.getElementById('next').onclick=()=>{{if(page<pages-1)page++;show();}};show();
}})();
</script></body></html>"""

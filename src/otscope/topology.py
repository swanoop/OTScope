"""Observed communication graph and a self-contained, offline report view."""
from __future__ import annotations

import json


def build_topology(result: dict, findings: list[dict] | None = None) -> dict:
    findings = findings if findings is not None else result.get("policy", {}).get("findings", [])
    by_conversation, by_asset = {}, {}
    for finding in findings:
        evidence = finding.get("evidence", {})
        if evidence.get("conversation"):
            by_conversation.setdefault(evidence["conversation"], []).append(finding)
        if evidence.get("ip"):
            by_asset.setdefault(evidence["ip"], []).append(finding)
    nodes = [{
        "id": asset["ip"], "label": asset.get("name", asset["ip"]),
        "zone_id": asset.get("zone_id"), "zone_name": asset.get("zone_name", "Unassigned"),
        "protocols": asset.get("protocols", []), "roles": asset.get("roles", []),
        "packets_tx": asset.get("packets_tx", 0), "packets_rx": asset.get("packets_rx", 0),
        "findings": by_asset.get(asset["ip"], []),
    } for asset in result.get("assets", [])]
    edges = [{
        "id": f"flow-{index}", "key": c["key"], "source": c["src"], "target": c["dst"],
        "protocol": c["protocol"], "transport": c["transport"], "service_port": c["service_port"],
        "packets": c["packets"], "bytes": c["bytes"],
        "first_seen": c.get("first_seen"), "last_seen": c.get("last_seen"),
        "policy": c.get("policy"), "evidence": c.get("evidence", {}),
        "semantics": {key: ([{k: v for k, v in target.items() if k != "evidence"} for target in value]
                            if key == "targets" else value)
                      for key, value in c.get("semantics", {}).items() if key != "operation_evidence"},
        "findings": by_conversation.get(c["key"], []),
    } for index, c in enumerate(result.get("conversations", []))]
    return {"schema_version": 1, "capture_sha256": result.get("capture", {}).get("sha256"),
            "policy_sha256": result.get("policy", {}).get("sha256"),
            "basis": "Observed directional IP conversations; this is not a physical network topology.",
            "nodes": nodes, "edges": edges}


def topology_html(result: dict, findings: list[dict] | None = None) -> str:
    # The HTML parser processes </script> even inside JSON strings. Escape '<'
    # before embedding untrusted analyst labels; render all labels with textContent.
    data = json.dumps(build_topology(result, findings), ensure_ascii=True, separators=(",", ":"))
    data = data.replace("<", r"\u003c").replace("&", r"\u0026")
    return _HTML + '<script id="map-data" type="application/json">' + data + "</script><script>" + _JS + "</script>"


_HTML = """
<style>
.map-controls{display:flex;flex-wrap:wrap;align-items:end;gap:12px;margin:14px 0}
.map-controls label{display:flex;flex-direction:column;gap:4px;font-size:14px}
.map-controls input,.map-controls select,#map-select{font:inherit;padding:8px;border:1px solid #94a3b8;border-radius:5px;max-width:100%}
.map-controls .map-check{flex-direction:row;align-items:center;padding:8px}
.map-layout{display:grid;grid-template-columns:minmax(0,2fr) minmax(260px,1fr);gap:14px}
.map-canvas{overflow:auto;max-height:650px;border:1px solid #cbd5e1;border-radius:8px;background:#fff}
#network-map{display:block;width:100%;min-width:720px}
#map-details{background:#fff;border:1px solid #cbd5e1;border-radius:8px;padding:16px;overflow:auto;max-height:618px;overflow-wrap:anywhere}
#map-details h3{margin-top:0}#map-details pre{font-size:12px}
.map-node{cursor:pointer}.map-node:focus rect,.map-node:hover rect{stroke:#0f172a;stroke-width:3}
.map-edge{fill:none;stroke-width:2;cursor:pointer;opacity:.8}
.map-edge:hover,.map-edge:focus{stroke-width:5;opacity:1;outline:none}
.map-legend{font-size:14px}.map-select-wrap{display:block;margin:12px 0}#map-select{width:100%}
@media(max-width:850px){.map-layout{grid-template-columns:1fr}}
</style>
<section aria-labelledby="map-heading">
<h2 id="map-heading">Observed communication map</h2>
<p>Arrows show observed traffic directions. Zones come from the supplied policy.
This view does not infer switches, wiring, or authorised transactions.
<a href="topology.json">Download the complete graph</a>.</p>
<div class="map-controls">
<label>Find a device<input id="map-search" type="search" placeholder="Name, IP or zone"></label>
<label>Protocol<select id="map-protocol"><option value="">All protocols</option></select></label>
<label>Zone<select id="map-zone"><option value="">All zones</option></select></label>
<label class="map-check"><input id="map-cross-zone" type="checkbox">Cross-zone only</label>
<button id="map-reset" type="button">Reset filters</button>
</div>
<p id="map-status" role="status" aria-live="polite"></p>
<p class="map-legend">Red: findings · Amber: operation checks incomplete · Blue: observed direction.
A blue connection does not establish that the traffic is safe.</p>
<div class="map-layout">
<div>
<div class="map-canvas"><svg id="network-map" role="group" aria-label="Observed directional conversations"></svg></div>
<label class="map-select-wrap" for="map-select">Select a visible device or conversation for details</label>
<select id="map-select"><option value="">Choose an item</option></select>
</div>
<aside id="map-details" aria-live="polite"><h3>Inspect the traffic</h3><p>Select a device or an arrow to see observations, policy status and packet evidence.</p></aside>
</div>
<noscript><p>Enable JavaScript for map filters. The tables below and topology.json contain the observations.</p></noscript>
</section>
"""

_JS = r"""
(() => {
"use strict";
const data = JSON.parse(document.getElementById("map-data").textContent);
const nodes = new Map(data.nodes.map(n => [n.id, n]));
const svg = document.getElementById("network-map");
const details = document.getElementById("map-details");
const search = document.getElementById("map-search");
const protocol = document.getElementById("map-protocol");
const zone = document.getElementById("map-zone");
const cross = document.getElementById("map-cross-zone");
const select = document.getElementById("map-select");
const ns = "http://www.w3.org/2000/svg";
const zoneKey = n => n.zone_id === null ? "__unassigned__" : "zone:" + n.zone_id;
const option = (parent, value, label) => {
    const element = document.createElement("option");
    element.value = value; element.textContent = label; parent.appendChild(element);
};
Array.from(new Set(data.edges.map(e => e.protocol))).sort().forEach(p => option(protocol, p, p));
const zones = new Map(data.nodes.map(n => [zoneKey(n), n.zone_name]));
Array.from(zones).sort((a,b) => a[1].localeCompare(b[1])).forEach(([key,name]) => option(zone, key, name));
function element(name, attrs, label) {
    const item = document.createElementNS(ns, name);
    Object.entries(attrs || {}).forEach(([key,value]) => item.setAttribute(key, value));
    if (label !== undefined) item.textContent = label;
    return item;
}
function line(label, value) {
    const p = document.createElement("p"), strong = document.createElement("strong");
    strong.textContent = label + ": "; p.appendChild(strong);
    p.appendChild(document.createTextNode(String(value))); details.appendChild(p);
}
function jsonBlock(label, value) {
    const wrapper = document.createElement("details"), summary = document.createElement("summary");
    summary.textContent = label; wrapper.appendChild(summary);
    const pre = document.createElement("pre"); pre.textContent = JSON.stringify(value, null, 2);
    wrapper.appendChild(pre); details.appendChild(wrapper);
}
function inspect(kind, item) {
    details.replaceChildren();
    const heading = document.createElement("h3");
    heading.textContent = kind === "node" ? item.label : nodes.get(item.source).label + " → " + nodes.get(item.target).label;
    details.appendChild(heading); select.value = kind + ":" + item.id;
    if (kind === "node") {
        line("IP", item.id); line("Zone", item.zone_name);
        line("Observed protocols", item.protocols.join(", "));
        line("Packets", item.packets_tx + " transmitted; " + item.packets_rx + " received");
        line("Inferred roles", item.roles.join(", ") || "No role inferred");
        const connected = data.edges.filter(e => e.source === item.id || e.target === item.id);
        line("Observed directions", connected.length);
        jsonBlock("Device findings", item.findings);
        jsonBlock("Findings on connected directions", connected.flatMap(e => e.findings));
    } else {
        line("Endpoints", item.source + " → " + item.target);
        line("Protocol / service", item.protocol + " / " + item.transport + " " + item.service_port);
        line("Packets / bytes", item.packets + " / " + item.bytes);
        line("Source zone", nodes.get(item.source).zone_name);
        line("Destination zone", nodes.get(item.target).zone_name);
        line("Policy status", item.policy ? item.policy.status.replace(/_/g, " ") : "No policy supplied");
        if (item.policy) {
            line("Matched rule", item.policy.rule_id || "None");
            line("Conduit", item.policy.conduit_id || "None");
            line("Requests checked", item.policy.requests_checked);
            line("Operations not decoded", item.policy.unknown_operations);
        }
        line("First observed packet filter", item.evidence.wireshark_filter || "Unavailable");
        line("Capture SHA-256", data.capture_sha256 || "Unavailable");
        if (data.policy_sha256) line("Policy SHA-256", data.policy_sha256);
        jsonBlock("Protocol observations", item.semantics);
        jsonBlock("Findings and packet evidence", item.findings);
    }
}
function actionable(item, kind, value) {
    item.setAttribute("tabindex", "0"); item.setAttribute("role", "button");
    item.addEventListener("click", () => inspect(kind, value));
    item.addEventListener("keydown", event => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); inspect(kind, value); }
    });
}
function render() {
    const query = search.value.trim().toLowerCase();
    const matches = n => [n.id, n.label, n.zone_name].some(s => s.toLowerCase().includes(query));
    const filtered = data.edges.filter(e => {
        const a = nodes.get(e.source), b = nodes.get(e.target);
        return (!protocol.value || e.protocol === protocol.value) && (!query || matches(a) || matches(b)) &&
            (!zone.value || zoneKey(a) === zone.value || zoneKey(b) === zone.value) &&
            (!cross.checked || (a.zone_id !== null && b.zone_id !== null && a.zone_id !== b.zone_id));
    });
    const wanted = new Set(filtered.flatMap(e => [e.source, e.target]));
    if (!protocol.value && !cross.checked) {
        data.nodes.filter(n => matches(n) && (!zone.value || zoneKey(n) === zone.value)).forEach(n => wanted.add(n.id));
    }
    const matchingNodes = data.nodes.filter(n => wanted.has(n.id));
    const shownNodes = matchingNodes.slice(0, 80), shownIDs = new Set(shownNodes.map(n => n.id));
    const shownEdges = filtered.filter(e => shownIDs.has(e.source) && shownIDs.has(e.target)).slice(0, 250);
    let status = "Showing " + shownNodes.length + " of " + matchingNodes.length + " matching devices and " +
        shownEdges.length + " of " + filtered.length + " matching directions.";
    if (shownNodes.length < matchingNodes.length || shownEdges.length < filtered.length)
        status += " View limited to 80 devices and 250 directions; narrow the filters or download topology.json.";
    if (!shownNodes.length) status += " No observations match these filters.";
    document.getElementById("map-status").textContent = status;
    svg.replaceChildren(); select.replaceChildren(); option(select, "", "Choose an item");
    details.replaceChildren();
    const prompt = document.createElement("p"); prompt.textContent = "Select a device or conversation for details.";
    details.appendChild(prompt);
    const defs = element("defs");
    [["blue","#2563eb"],["red","#b91c1c"],["amber","#a16207"]].forEach(([id,color]) => {
        const marker = element("marker", {id:"map-arrow-"+id, viewBox:"0 0 10 10", refX:"9", refY:"5",
            markerWidth:"6", markerHeight:"6", orient:"auto-start-reverse"});
        marker.appendChild(element("path", {d:"M 0 0 L 10 5 L 0 10 z", fill:color})); defs.appendChild(marker);
    });
    svg.appendChild(defs);
    const groups = new Map();
    shownNodes.forEach(n => { const k = zoneKey(n); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(n); });
    const entries = Array.from(groups), positions = new Map();
    let top = 12;
    for (let start=0; start<entries.length; start+=3) {
        const row = entries.slice(start, start+3);
        const height = Math.max(...row.map(([,items]) => items.length)) * 64 + 62;
        row.forEach(([key,items], column) => {
            const left = 12 + column * 396;
            svg.appendChild(element("rect", {x:left,y:top,width:384,height:height-12,rx:10,fill:"#f1f5f9",stroke:"#cbd5e1"}));
            const label = element("text", {x:left+14,y:top+25,fill:"#334155","font-size":15,"font-weight":600},
                zones.get(key).slice(0, 38));
            label.appendChild(element("title", {}, zones.get(key))); svg.appendChild(label);
            items.forEach((n,i) => positions.set(n.id, {x:left+192,y:top+65+i*64}));
        });
        top += height;
    }
    svg.setAttribute("viewBox", "0 0 1200 " + Math.max(top, 160));
    shownEdges.forEach((e,index) => {
        const a=positions.get(e.source), b=positions.get(e.target);
        let path;
        if (a.x === b.x) {
            const bend=130+(index%4)*14;
            path="M "+(a.x+100)+" "+a.y+" C "+(a.x+bend)+" "+(a.y-35)+", "+(b.x+bend)+" "+(b.y+35)+", "+(b.x+100)+" "+b.y;
        } else {
            const direction=a.x<b.x?1:-1, x1=a.x+104*direction, x2=b.x-104*direction;
            const bend=(index%5-2)*14, middle=(x1+x2)/2;
            path="M "+x1+" "+a.y+" C "+middle+" "+(a.y+bend)+", "+middle+" "+(b.y+bend)+", "+x2+" "+b.y;
        }
        const color=e.findings.length?"red":e.policy&&e.policy.status==="not_evaluated"?"amber":"blue";
        const stroke={red:"#b91c1c",amber:"#a16207",blue:"#2563eb"}[color];
        const label=nodes.get(e.source).label+" → "+nodes.get(e.target).label+" ("+e.protocol+")";
        const edge=element("path", {d:path,stroke:stroke,"marker-end":"url(#map-arrow-"+color+")",
            class:"map-edge","aria-label":label,"data-edge-id":e.id});
        edge.appendChild(element("title",{},label)); actionable(edge,"edge",e); svg.appendChild(edge);
        option(select,"edge:"+e.id,label);
    });
    shownNodes.forEach(n => {
        const p=positions.get(n.id), group=element("g",{class:"map-node","aria-label":n.label+" "+n.id,"data-node-id":n.id});
        group.appendChild(element("rect",{x:p.x-104,y:p.y-23,width:208,height:46,rx:7,fill:"#fff",stroke:"#64748b"}));
        group.appendChild(element("text",{x:p.x,y:p.y-4,"text-anchor":"middle","font-size":13,fill:"#17202a"},n.label.slice(0,27)));
        group.appendChild(element("text",{x:p.x,y:p.y+13,"text-anchor":"middle","font-size":11,fill:"#475569"},n.id));
        group.appendChild(element("title",{},n.label+" · "+n.id+" · "+n.zone_name));
        actionable(group,"node",n); svg.appendChild(group); option(select,"node:"+n.id,n.label+" ("+n.id+")");
    });
}
select.addEventListener("change", () => {
    if (!select.value) return;
    const split=select.value.indexOf(":"), kind=select.value.slice(0,split), id=select.value.slice(split+1);
    const item=kind==="node"?nodes.get(id):data.edges.find(e=>e.id===id);
    if (item) inspect(kind,item);
});
search.addEventListener("input",render);
[protocol,zone,cross].forEach(control => control.addEventListener("change",render));
document.getElementById("map-reset").addEventListener("click",() => {
    search.value="";protocol.value="";zone.value="";cross.checked=false;render();
});
render();
})();
"""

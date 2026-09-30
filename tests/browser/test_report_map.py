"""Real Chromium checks for the file:// report; Playwright is a CI/dev dependency."""
import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")

from otscope.analyzer import analyze_capture
from otscope.policy import NetworkPolicy
from otscope.report import write_outputs

ROOT = Path(__file__).parents[2]


@pytest.fixture
def report_data(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "examples/generate_policy_demo.py"), str(tmp_path)], check=True)
    document = json.loads((ROOT / "examples/lab_policy.json").read_text())
    return analyze_capture(tmp_path / "policy_changed.pcap", policy=NetworkPolicy(document))


@pytest.fixture
def page():
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page()
        errors, remote_requests = [], []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: remote_requests.append(request.url)
                if request.url.startswith(("http:", "https:")) else None)
        yield page
        browser.close()
        assert errors == []
        assert remote_requests == []


def test_offline_map_filters_and_keyboard_details(page, report_data, tmp_path):
    report = write_outputs(report_data, tmp_path / "report")
    page.goto(report.as_uri())
    assert page.locator(".map-node").count() == 5
    assert page.locator(".map-edge").count() == 5
    page.get_by_label("Find a device").fill("Historian")
    assert page.locator(".map-node").count() == 2
    assert page.locator(".map-edge").count() == 1
    page.locator(".map-edge").focus()
    page.keyboard.press("Enter")
    assert "historian-reads" in page.locator("#map-details").inner_text()
    assert "violation" in page.locator("#map-details").inner_text()
    assert "frame.number" in page.locator("#map-details").inner_text()
    page.locator("#map-details summary").last.click()
    assert "policy_operation_denied" in page.locator("#map-details").inner_text()
    page.get_by_role("button", name="Reset filters").click()
    page.get_by_label("Zone", exact=True).select_option("zone:monitoring")
    assert page.locator(".map-edge").count() == 1
    page.get_by_role("button", name="Reset filters").click()
    page.get_by_label("Cross-zone only").check()
    assert page.locator(".map-edge").count() == 5
    page.get_by_label("Protocol", exact=True).select_option("modbus")
    assert page.locator(".map-edge").count() == 5
    page.locator("#map-select").select_option("node:10.20.40.20")
    assert "Lab PLC" in page.locator("#map-details").inner_text()
    page.get_by_label("Find a device").fill("no-such-device")
    assert page.locator(".map-node").count() == 0
    assert "No observations match" in page.locator("#map-status").inner_text()


def test_report_labels_cannot_execute_script(page, report_data, tmp_path):
    hostile = '</script><script>window.pwned=true</script><img src=x onerror="window.pwned=true">'
    report_data["assets"][0]["name"] = hostile
    report_data["assets"][0]["zone_name"] = hostile
    report = write_outputs(report_data, tmp_path / "report")
    page.goto(report.as_uri())
    page.locator("#map-select").select_option("node:" + report_data["assets"][0]["ip"])
    assert hostile in page.locator("#map-details").inner_text()
    assert page.evaluate("window.pwned === undefined")
    assert page.locator("#map-details img").count() == 0


def test_large_graph_is_bounded_with_complete_export(page, report_data, tmp_path):
    sample = report_data["assets"][0]
    report_data["assets"] = [
        {**copy.deepcopy(sample), "ip": f"10.99.0.{index}", "name": f"Device {index}"}
        for index in range(1, 91)
    ]
    report_data["conversations"] = []
    report = write_outputs(report_data, tmp_path / "report")
    page.goto(report.as_uri())
    assert page.locator(".map-node").count() == 80
    assert "80 of 90" in page.locator("#map-status").inner_text()
    assert "View limited" in page.locator("#map-status").inner_text()
    assert len(json.loads((report.parent / "topology.json").read_text())["nodes"]) == 90
    page.get_by_label("Find a device").fill("10.99.0.90")
    assert page.locator(".map-node").count() == 1

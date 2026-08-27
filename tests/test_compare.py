from otscope.compare import compare


def conv(fc, access):
    return {
        "key": "a|b|tcp|502|modbus",
        "src": "a", "dst": "b", "transport": "tcp", "service_port": 502, "protocol": "modbus",
        "packets": 20, "packet_rate": 1.0,
        "semantics": {"function_codes": fc, "access": access},
    }


def test_new_modbus_write_is_critical():
    baseline = {"assets": [{"ip": "a"}, {"ip": "b"}], "conversations": [conv([3], ["read"])]}
    current = {"assets": [{"ip": "a"}, {"ip": "b"}], "conversations": [conv([3, 16], ["read", "write"])]}
    findings = compare(baseline, current)
    assert any(x["kind"] == "new_modbus_write" and x["severity"] == "CRITICAL" for x in findings)

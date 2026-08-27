import struct

from otscope.protocols import iec104, modbus, s7


def test_modbus_read_and_write():
    read = struct.pack("!HHHB", 1, 0, 6, 1) + bytes([3]) + struct.pack("!HH", 10, 5)
    r = modbus.parse(read, request=True)
    assert r["function_code"] == 3
    assert r["access"] == "read"
    assert r["address_start"] == 10
    assert r["quantity"] == 5

    write = struct.pack("!HHHB", 2, 0, 6, 1) + bytes([16]) + struct.pack("!HH", 100, 3)
    w = modbus.parse(write, request=True)
    assert w["access"] == "write"
    assert w["address_start"] == 100


def test_iec104_command():
    asdu = bytes([45, 1]) + struct.pack("<H", 6) + struct.pack("<H", 1) + b"\x01\x00\x00\x01"
    apdu = b"\x00\x00\x00\x00" + asdu
    parsed = iec104.parse(bytes([0x68, len(apdu)]) + apdu, request=True)
    assert parsed["type_id"] == 45
    assert parsed["access"] == "command"


def test_s7_read():
    s7_data = b"\x32\x01\x00\x00\x00\x01\x00\x01\x00\x00\x04"
    parsed = s7.parse(b"\x03\x00\x00\x12\x02\xf0\x80" + s7_data, request=True)
    assert parsed["function"] == 4
    assert parsed["access"] == "read"

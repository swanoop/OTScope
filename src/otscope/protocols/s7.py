from __future__ import annotations

from typing import Any

ROSCTR = {1: "job", 2: "ack", 3: "ack_data", 7: "user_data"}
FUNCTIONS = {
    0x04: "Read Var",
    0x05: "Write Var",
    0x1A: "Request Download",
    0x1B: "Download Block",
    0x1C: "Download Ended",
    0x1D: "Start Upload",
    0x1E: "Upload",
    0x1F: "End Upload",
    0x28: "PI Service",
    0x29: "PLC Stop",
}
WRITE_OR_ENGINEERING = {0x05, 0x1A, 0x1B, 0x1C, 0x28, 0x29}


def parse(payload: bytes, *, request: bool) -> dict[str, Any] | None:
    pos = 0
    if payload.startswith(b"\x03\x00"):
        if len(payload) < 7 or int.from_bytes(payload[2:4], "big") != len(payload):
            return None
        cotp_len = payload[4]
        if cotp_len < 2 or payload[5] != 0xF0 or not payload[6] & 0x80:
            return None
        pos = 5 + cotp_len
    if len(payload) < pos + 10 or payload[pos] != 0x32:
        return None
    p = payload[pos:]
    rosctr = p[1]
    if rosctr not in ROSCTR:
        return None
    header_len = 12 if rosctr in {2, 3} else 10
    if len(p) < header_len:
        return None
    param_len = int.from_bytes(p[6:8], "big")
    data_len = int.from_bytes(p[8:10], "big")
    if header_len + param_len + data_len != len(p):
        return None
    params = p[header_len:header_len + param_len]
    func = params[0] if params and rosctr in {1, 3} else None
    access = "other"
    if func == 0x04:
        access = "read"
    elif func in WRITE_OR_ENGINEERING:
        access = "engineering" if func != 0x05 else "write"
    return {
        "rosctr": rosctr,
        "rosctr_name": ROSCTR.get(rosctr, f"rosctr_{rosctr}"),
        "function": func,
        "function_name": FUNCTIONS.get(func, f"Function 0x{func:02x}" if func is not None else "Unknown"),
        "request": request,
        "access": access,
    }

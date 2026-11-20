"""Conservative DNP3 data-link and single-fragment application decoder.

Only CRC-valid link frames with complete transport/application fragments are
interpreted as operations. Segmented application messages are explicitly
labelled as undecoded rather than guessing their function codes.
"""
from __future__ import annotations

from typing import Any

FUNCTIONS = {
    0: "Confirm", 1: "Read", 2: "Write", 3: "Select", 4: "Operate",
    5: "Direct Operate", 6: "Direct Operate No Ack", 7: "Immediate Freeze",
    8: "Immediate Freeze No Ack", 9: "Freeze and Clear",
    10: "Freeze and Clear No Ack", 11: "Freeze at Time",
    12: "Freeze at Time No Ack", 13: "Cold Restart", 14: "Warm Restart",
    15: "Initialize Data", 16: "Initialize Application", 17: "Start Application",
    18: "Stop Application", 19: "Save Configuration",
    20: "Enable Unsolicited", 21: "Disable Unsolicited", 22: "Assign Class",
    23: "Delay Measurement", 24: "Record Current Time", 25: "Open File",
    26: "Close File", 27: "Delete File", 28: "Get File Info",
    29: "Authenticate File", 30: "Abort File", 31: "Activate Configuration",
    129: "Response", 130: "Unsolicited Response", 131: "Authentication Response",
}
CONTROL_FUNCTIONS = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
RESTART_FUNCTIONS = {13, 14, 16, 18, 31}
FILE_FUNCTIONS = set(range(25, 31))
SENSITIVE_FUNCTIONS = CONTROL_FUNCTIONS | RESTART_FUNCTIONS | FILE_FUNCTIONS


def _crc(data: bytes) -> int:
    crc = 0
    for octet in data:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA6BC if crc & 1 else 0)
    return (~crc) & 0xFFFF


def frame_length(prefix: bytes) -> int | None:
    if len(prefix) < 3 or prefix[:2] != b"\x05\x64":
        return None
    length = prefix[2]
    if not 5 <= length <= 255:
        return None
    user_data_len = length - 5
    return 10 + user_data_len + 2 * ((user_data_len + 15) // 16)


def parse(payload: bytes, *, request: bool) -> dict[str, Any] | None:
    length = frame_length(payload)
    if length is None or len(payload) != length:
        return None
    if _crc(payload[:8]) != int.from_bytes(payload[8:10], "little"):
        return None
    content_len = payload[2] - 5
    position, user = 10, bytearray()
    while len(user) < content_len:
        size = min(16, content_len-len(user))
        block = payload[position:position+size]
        if _crc(block) != int.from_bytes(payload[position+size:position+size+2], "little"):
            return None
        user.extend(block)
        position += size + 2
    out: dict[str, Any] = {
        "link_source": int.from_bytes(payload[6:8], "little"),
        "link_destination": int.from_bytes(payload[4:6], "little"),
        "link_control": payload[3],
        "request": request,
    }
    if not user:
        out.update(access="link_only", decode_status="link_only")
        return out
    transport = user[0]
    out.update(transport_sequence=transport & 0x3F,
               transport_first=bool(transport & 0x40),
               transport_final=bool(transport & 0x80))
    if transport & 0xC0 != 0xC0 or len(user) < 3:
        out.update(access="undecoded", decode_status="segmented_or_incomplete")
        return out
    application_control = user[1]
    if application_control & 0xC0 != 0xC0:
        out.update(access="undecoded", decode_status="segmented_application")
        return out
    fc = user[2]
    out.update(function_code=fc, function_name=FUNCTIONS.get(fc, f"Function {fc}"),
               application_sequence=application_control & 0x0F,
               access="control" if fc in CONTROL_FUNCTIONS else
                      "engineering" if fc in RESTART_FUNCTIONS | FILE_FUNCTIONS else
                      "read" if fc == 1 else "other",
               decode_status="decoded")
    return out

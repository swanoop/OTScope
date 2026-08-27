from __future__ import annotations

import struct
from typing import Any

FUNCTIONS = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    43: "Encapsulated Interface Transport",
}

WRITE_FUNCTIONS = {5, 6, 15, 16, 22, 23}
READ_FUNCTIONS = {1, 2, 3, 4}


def parse(payload: bytes, *, request: bool) -> dict[str, Any] | None:
    if len(payload) < 8:
        return None
    transaction_id, protocol_id, length = struct.unpack("!HHH", payload[:6])
    if protocol_id != 0 or length < 2:
        return None
    unit_id = payload[6]
    fc_raw = payload[7]
    exception = bool(fc_raw & 0x80)
    fc = fc_raw & 0x7F
    out: dict[str, Any] = {
        "transaction_id": transaction_id,
        "unit_id": unit_id,
        "function_code": fc,
        "function_name": FUNCTIONS.get(fc, f"Function {fc}"),
        "request": request,
        "exception": exception,
        "access": "write" if fc in WRITE_FUNCTIONS else "read" if fc in READ_FUNCTIONS else "other",
    }
    if exception and len(payload) >= 9:
        out["exception_code"] = payload[8]
        return out
    if not request:
        return out

    pdu = payload[8:]
    try:
        if fc in {1, 2, 3, 4, 5, 6, 15, 16} and len(pdu) >= 4:
            address, value_or_qty = struct.unpack("!HH", pdu[:4])
            out["address_start"] = address
            out["quantity"] = 1 if fc in {5, 6} else value_or_qty
            if fc in {5, 6}:
                out["value"] = value_or_qty
        elif fc == 22 and len(pdu) >= 6:
            address, and_mask, or_mask = struct.unpack("!HHH", pdu[:6])
            out.update(address_start=address, quantity=1, and_mask=and_mask, or_mask=or_mask)
        elif fc == 23 and len(pdu) >= 8:
            read_addr, read_qty, write_addr, write_qty = struct.unpack("!HHHH", pdu[:8])
            out.update(
                read_address_start=read_addr,
                read_quantity=read_qty,
                write_address_start=write_addr,
                write_quantity=write_qty,
            )
    except struct.error:
        pass
    return out

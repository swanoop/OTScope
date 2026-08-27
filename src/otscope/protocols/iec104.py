from __future__ import annotations

from typing import Any

TYPE_NAMES = {
    1: "M_SP_NA_1 Single-point information",
    3: "M_DP_NA_1 Double-point information",
    9: "M_ME_NA_1 Measured value, normalized",
    11: "M_ME_NB_1 Measured value, scaled",
    13: "M_ME_NC_1 Measured value, short float",
    30: "M_SP_TB_1 Single-point with CP56Time2a",
    31: "M_DP_TB_1 Double-point with CP56Time2a",
    45: "C_SC_NA_1 Single command",
    46: "C_DC_NA_1 Double command",
    47: "C_RC_NA_1 Regulating step command",
    48: "C_SE_NA_1 Set-point normalized",
    49: "C_SE_NB_1 Set-point scaled",
    50: "C_SE_NC_1 Set-point short float",
    51: "C_BO_NA_1 Bitstring command",
    58: "C_SC_TA_1 Single command with time",
    59: "C_DC_TA_1 Double command with time",
    60: "C_RC_TA_1 Regulating command with time",
    61: "C_SE_TA_1 Set-point normalized with time",
    62: "C_SE_TB_1 Set-point scaled with time",
    63: "C_SE_TC_1 Set-point short float with time",
    64: "C_BO_TA_1 Bitstring command with time",
    100: "C_IC_NA_1 Interrogation command",
    101: "C_CI_NA_1 Counter interrogation",
    102: "C_RD_NA_1 Read command",
    103: "C_CS_NA_1 Clock synchronization",
    104: "C_TS_NA_1 Test command",
    105: "C_RP_NA_1 Reset process command",
}
COMMAND_TYPES = set(range(45, 52)) | set(range(58, 65)) | {100, 101, 102, 103, 104, 105}


def parse(payload: bytes, *, request: bool) -> dict[str, Any] | None:
    if len(payload) < 6 or payload[0] != 0x68:
        return None
    apdu_len = payload[1]
    if apdu_len + 2 > len(payload):
        return None
    control = payload[2:6]
    if control[0] & 0x01:
        kind = "S" if (control[0] & 0x03) == 1 else "U"
        return {"frame_type": kind, "request": request, "access": "control"}

    if len(payload) < 12:
        return {"frame_type": "I", "request": request, "access": "data"}
    asdu = payload[6:]
    type_id = asdu[0]
    vsq = asdu[1]
    cot = int.from_bytes(asdu[2:4], "little") & 0x3F
    common_address = int.from_bytes(asdu[4:6], "little")
    ioa = int.from_bytes(asdu[6:9], "little") if len(asdu) >= 9 else None
    return {
        "frame_type": "I",
        "type_id": type_id,
        "type_name": TYPE_NAMES.get(type_id, f"Type {type_id}"),
        "cause_of_transmission": cot,
        "common_address": common_address,
        "information_object_address": ioa,
        "objects": vsq & 0x7F,
        "sequence": bool(vsq & 0x80),
        "request": request,
        "access": "command" if type_id in COMMAND_TYPES else "telemetry",
    }

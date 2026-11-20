"""Property-based resilience tests; run in CI with the dev dependencies."""
from __future__ import annotations

import struct

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402 - optional Hypothesis check precedes imports
from otscope.protocols import dnp3, iec104, modbus, s7  # noqa: E402 - optional Hypothesis check precedes imports
from otscope.analyzer import _app_protocol  # noqa: E402 - optional Hypothesis check precedes imports


@settings(max_examples=250, deadline=None)
@given(st.binary(max_size=2048), st.booleans())
def test_decoders_never_raise_on_arbitrary_capture_bytes(payload: bytes, request: bool):
    for decoder in (dnp3, iec104, modbus, s7):
        result = decoder.parse(payload, request=request)
        assert result is None or isinstance(result, dict)
    protocol, port = _app_protocol("tcp", 60001, 5020, payload)
    assert isinstance(protocol, str) and isinstance(port, int)


@settings(max_examples=250, deadline=None)
@given(st.integers(min_value=0, max_value=255), st.binary(max_size=32), st.booleans())
def test_mutated_dnp3_application_frames_fail_closed(fc: int, data: bytes, corrupt: bool):
    application = bytes((0xC0, 0xC0, fc)) + data
    if len(application) > 16:
        application = application[:16]
    header = b"\x05\x64" + bytes((5 + len(application), 0xC4)) + struct.pack("<HH", 1, 2)
    packet = header + struct.pack("<H", dnp3._crc(header))
    packet += application + struct.pack("<H", dnp3._crc(application))
    if corrupt:
        packet = packet[:-1] + bytes((packet[-1] ^ 1,))
    decoded = dnp3.parse(packet, request=True)
    if corrupt:
        assert decoded is None
    else:
        assert decoded is not None and decoded.get("function_code") == fc

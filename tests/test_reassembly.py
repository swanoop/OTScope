import pytest

from otscope.analyzer import analyze_capture
from otscope.models import TransportPacket
from otscope.reassembly import TCPReassembler


def operations(result):
    return [event for event in result["timeline"] if event["category"] == "protocol_operation"]


@pytest.mark.parametrize("protocol,port", [("modbus", 502), ("iec104", 2404), ("s7", 102)])
def test_split_reordered_messages_keep_all_packet_evidence(packets, capture, protocol, port):
    payload = {"modbus": packets["modbus_req"](6, 900, 1),
               "iec104": packets["iec104_command"](), "s7": packets["s7_job"](0x29)}[protocol]
    path = capture([payload[4:9], payload[9:], payload[:4]], seqs=[5, 10, 1], port=port)
    result = analyze_capture(path)
    events = operations(result)
    assert len(events) == 1
    assert events[0]["evidence"]["frame_numbers"] == [1, 2, 3]
    assert events[0]["evidence"]["capture_sha256"] == result["capture"]["sha256"]
    assert events[0]["evidence"]["wireshark_filter"] == "frame.number in {1 2 3}"
    assert result["coverage"]["warnings"] == []


@pytest.mark.parametrize("protocol,port", [("modbus", 502), ("iec104", 2404), ("s7", 102)])
def test_multiple_messages_in_one_segment(packets, capture, protocol, port):
    pairs = {"modbus": (packets["modbus_req"](3, 0, 10), packets["modbus_req"](6, 900, 1)),
             "iec104": (packets["iec104_command"](102), packets["iec104_command"](45)),
             "s7": (packets["s7_job"](4), packets["s7_job"](0x29))}
    result = analyze_capture(capture([b"".join(pairs[protocol])], port=port))
    assert len(operations(result)) == 2
    assert all(e["evidence"]["frame_numbers"] == [1] for e in operations(result))


def test_retransmitted_bytes_do_not_duplicate_operations(packets, capture):
    payload = packets["modbus_req"](6, 100, 1)
    result = analyze_capture(capture([payload[:8], payload[:8], payload[6:]], seqs=[1, 1, 7]))
    assert len(operations(result)) == 1
    assert operations(result)[0]["evidence"]["frame_numbers"] == [1, 3]
    assert result["coverage"]["tcp_reassembly"]["retransmitted_bytes"] == 10


def test_missing_tcp_bytes_are_not_joined(packets, capture):
    payload = packets["modbus_req"](6, 100, 1)
    result = analyze_capture(capture([payload[:8], payload[10:]], seqs=[1, 11]))
    assert operations(result) == []
    assert result["coverage"]["tcp_reassembly"]["gap_bytes"] == 2
    assert result["coverage"]["warnings"]


def test_conflicting_overlap_excludes_ambiguous_stream(packets, capture):
    first = packets["modbus_req"](6, 100, 1)
    second = packets["modbus_req"](6, 900, 1)
    result = analyze_capture(capture([first, second], seqs=[1, 1]))
    assert operations(result) == []
    assert result["coverage"]["tcp_reassembly"]["conflicting_overlap_streams"] == 1
    assert any("Conflicting" in text for text in result["coverage"]["warnings"])


def test_tcp_sequence_wrap(packets, capture):
    payload = packets["modbus_req"](6, 100, 1)
    result = analyze_capture(capture([payload[:8], payload[8:]], seqs=[0xFFFFFFF8, 0]))
    assert len(operations(result)) == 1
    assert not result["coverage"]["warnings"]


def test_new_syn_starts_new_session_on_reused_ports(packets, capture):
    first, second = packets["modbus_req"](6, 100, 1), packets["modbus_req"](6, 900, 1)
    result = analyze_capture(capture([b"", first, b"", second],
                                     seqs=[10, 11, 20, 21], flags=[2, 0x18, 2, 0x18]))
    assert len(operations(result)) == 2
    assert not result["coverage"]["warnings"]


def test_capture_interfaces_never_share_a_tcp_stream(packets):
    payload = packets["modbus_req"](6, 100, 1)
    engine = TCPReassembler()
    for interface, data, sequence in [("0:0", payload[:8], 1), ("0:1", payload[8:], 9)]:
        engine.feed(TransportPacket(1, "a", "b", "tcp", 40000, 502, data, len(data),
                                    sequence=sequence, frame_number=1, interface_id=interface), "modbus")
    assert engine.finish() == []
    assert engine.stats["incomplete_regions"] == 2


def test_window_flush_preserves_incomplete_tail_and_deduplicates(packets):
    payload = packets["modbus_req"](6, 100, 1)
    engine = TCPReassembler(window_bytes=8)
    messages = []
    for frame, (data, seq) in enumerate([(payload[:8], 1), (payload[8:], 9), (payload, 1)], 1):
        messages.extend(engine.feed(TransportPacket(frame, "a", "b", "tcp", 40000, 502,
                                                    data, len(data), sequence=seq, frame_number=frame), "modbus"))
    messages.extend(engine.finish())
    assert len(messages) == 1
    assert engine.stats["retransmitted_bytes"] == len(payload)
    assert engine.stats["incomplete_regions"] == 0


def test_stream_limit_is_reported(packets):
    engine = TCPReassembler(max_streams=1)
    payload = packets["modbus_req"](6, 100, 1)
    messages = []
    for number in range(2):
        messages.extend(engine.feed(TransportPacket(number, str(number), "b", "tcp", 40000, 502,
                                                    payload, len(payload), sequence=1, frame_number=number+1), "modbus"))
    messages.extend(engine.finish())
    assert len(messages) == 2
    assert engine.stats["streams_evicted"] == 1


def test_fin_before_missing_segment_does_not_end_reconstruction(packets, capture):
    payload = packets["modbus_req"](6, 100, 1)
    result = analyze_capture(capture([payload[:8], b"", payload[8:], payload],
                                     seqs=[1, 13, 9, 1], flags=[0x18, 0x11, 0x18, 0x19]))
    assert len(operations(result)) == 1
    assert not result["coverage"]["warnings"]


def test_syn_makes_missing_initial_bytes_visible(packets, capture):
    payload = packets["modbus_req"](6, 100, 1)
    result = analyze_capture(capture([b"", payload], seqs=[100, 200], flags=[2, 0x18]))
    assert result["coverage"]["tcp_reassembly"]["gap_bytes"] == 99
    assert result["coverage"]["warnings"]

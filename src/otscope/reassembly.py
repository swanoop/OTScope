"""Bounded, offline TCP reconstruction for the three decoded OT protocols.

Segments are ordered within a capture window before messages are emitted. A
gap is never filled with invented bytes. Conflicting overlaps are excluded
from semantic decoding, and every discarded or incomplete region is counted.
"""
from __future__ import annotations

from collections import Counter, OrderedDict
from dataclasses import dataclass, field

from .models import TransportPacket


@dataclass
class Span:
    start: int
    end: int
    packet: TransportPacket


@dataclass
class Chunk:
    start: int
    data: bytes | bytearray
    spans: list[Span]

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass
class Message:
    protocol: str
    packet: TransportPacket
    payload: bytes
    spans: list[Span]

    def evidence(self) -> dict:
        frames = sorted({s.packet.frame_number for s in self.spans})
        return {
            "frame_numbers": frames,
            "first_seen": min(s.packet.timestamp for s in self.spans),
            "last_seen": max(s.packet.timestamp for s in self.spans),
            "interface_id": self.packet.interface_id,
            "wireshark_filter": "frame.number in {" + " ".join(map(str, frames)) + "}",
        }


@dataclass
class Stream:
    protocol: str
    packet: TransportPacket
    anchor: int
    syn_sequence: int | None = None
    chunks: list[Chunk] = field(default_factory=list)
    buffered: int = 0
    consumed: int | None = None
    history: bytes = b""
    poisoned: bool = False


class TCPReassembler:
    def __init__(self, window_bytes: int = 1_048_576, max_streams: int = 1024,
                 max_buffer_bytes: int = 16_777_216):
        if min(window_bytes, max_streams, max_buffer_bytes) <= 0:
            raise ValueError("TCP reconstruction limits must be positive")
        self.window_bytes = window_bytes
        self.max_streams = max_streams
        self.max_buffer_bytes = max_buffer_bytes
        self.streams: OrderedDict[tuple, Stream] = OrderedDict()
        self.stats: Counter = Counter()

    @staticmethod
    def _key(pkt: TransportPacket) -> tuple:
        return pkt.interface_id, pkt.src, pkt.dst, pkt.sport, pkt.dport

    def feed(self, pkt: TransportPacket, protocol: str) -> list[Message]:
        key = self._key(pkt)
        reverse = (pkt.interface_id, pkt.dst, pkt.src, pkt.dport, pkt.sport)
        messages: list[Message] = []
        syn = bool(pkt.flags & 0x02)
        existing = self.streams.get(key)
        if syn and (existing is None or existing.syn_sequence != pkt.sequence):
            # A new initiating SYN also retires the previous reverse direction.
            for old_key in (key, reverse) if not pkt.flags & 0x10 else (key,):
                old = self.streams.pop(old_key, None)
                if old:
                    messages.extend(self._flush(old, final=True))
        stream = self.streams.get(key)
        if stream is None:
            if not pkt.payload and not syn:
                return messages
            if len(self.streams) >= self.max_streams:
                _, old = self.streams.popitem(last=False)
                messages.extend(self._flush(old, final=True))
                self.stats["streams_evicted"] += 1
            stream = Stream(protocol, pkt, pkt.sequence,
                            pkt.sequence if syn else None)
            if syn:
                stream.consumed = pkt.sequence + 1
            self.streams[key] = stream
        self.streams.move_to_end(key)
        if pkt.payload and not stream.poisoned:
            sequence = (pkt.sequence + int(syn)) & 0xFFFFFFFF
            # Unwrap relative to the most recent sequence position, including
            # captures crossing the 32-bit TCP sequence boundary.
            delta = ((sequence - (stream.anchor & 0xFFFFFFFF) + 2**31) % 2**32) - 2**31
            start = stream.anchor + delta
            stream.anchor = max(stream.anchor, start + len(pkt.payload))
            data = pkt.payload
            if stream.consumed is not None and start < stream.consumed:
                overlap = min(len(data), stream.consumed - start)
                history_start = stream.consumed - len(stream.history)
                check_start = max(start, history_start)
                check_end = min(start + overlap, stream.consumed)
                if check_end > check_start and data[check_start-start:check_end-start] != stream.history[check_start-history_start:check_end-history_start]:
                    self.stats["conflicting_overlap_streams"] += 1
                    stream.poisoned = True
                    stream.chunks.clear()
                    stream.buffered = 0
                    return messages
                if start < history_start:
                    self.stats["late_unverified_bytes"] += min(overlap, history_start-start)
                self.stats["retransmitted_bytes"] += overlap
                data, start = data[overlap:], start + overlap
            if data:
                stream.chunks.append(Chunk(start, data, [Span(start, start+len(data), pkt)]))
                stream.buffered += len(data)
                if stream.buffered >= self.window_bytes:
                    messages.extend(self._flush(stream, final=False))
                    self.stats["window_flushes"] += 1
        elif pkt.payload:
            self.stats["ambiguous_bytes_skipped"] += len(pkt.payload)
        # Retain FIN/RST directions until a new SYN, eviction or EOF. Offline
        # captures can contain late/retransmitted data after the closing frame.
        while sum(s.buffered for s in self.streams.values()) > self.max_buffer_bytes:
            _, old = self.streams.popitem(last=False)
            messages.extend(self._flush(old, final=True))
            self.stats["streams_evicted"] += 1
        return messages

    def finish(self) -> list[Message]:
        messages = []
        while self.streams:
            _, stream = self.streams.popitem(last=False)
            messages.extend(self._flush(stream, final=True))
        return messages

    def _flush(self, stream: Stream, *, final: bool) -> list[Message]:
        if not stream.chunks:
            return []
        chunks = sorted(stream.chunks, key=lambda c: (c.start, c.spans[0].packet.frame_number))
        runs: list[Chunk] = []
        current = Chunk(chunks[0].start, bytearray(chunks[0].data), list(chunks[0].spans))
        for chunk in chunks[1:]:
            if chunk.start > current.end:
                runs.append(current)
                current = Chunk(chunk.start, bytearray(chunk.data), list(chunk.spans))
                continue
            overlap = min(len(chunk.data), current.end - chunk.start)
            offset = chunk.start - current.start
            if chunk.data[:overlap] != current.data[offset:offset+overlap]:
                self.stats["conflicting_overlap_streams"] += 1
                self.stats["ambiguous_bytes_skipped"] += stream.buffered
                stream.poisoned = True
                stream.chunks.clear()
                stream.buffered = 0
                return []
            self.stats["retransmitted_bytes"] += overlap
            if overlap < len(chunk.data):
                new_start = chunk.start + overlap
                current.data += chunk.data[overlap:]
                current.spans.extend(Span(max(s.start, new_start), s.end, s.packet)
                                     for s in chunk.spans if s.end > new_start)
        runs.append(current)
        stream.chunks, stream.buffered = [], 0
        messages: list[Message] = []
        for index, run in enumerate(runs):
            if stream.consumed is not None and run.start > stream.consumed:
                self.stats["gap_events"] += 1
                self.stats["gap_bytes"] += run.start - stream.consumed
            is_final = final or index < len(runs)-1
            framed, consumed = self._frame(stream.protocol, run, final=is_final)
            messages.extend(framed)
            if consumed:
                if stream.consumed != run.start:
                    stream.history = b""
                stream.history = (stream.history + bytes(run.data[:consumed]))[-65536:]
                stream.consumed = run.start + consumed
            if consumed < len(run.data):
                start = run.start + consumed
                spans = [Span(max(s.start, start), s.end, s.packet)
                         for s in run.spans if s.end > start]
                tail = Chunk(start, bytes(run.data[consumed:]), spans)
                stream.chunks.append(tail)
                stream.buffered += len(tail.data)
        return messages

    def _frame(self, protocol: str, run: Chunk, *, final: bool) -> tuple[list[Message], int]:
        data, pos, messages = run.data, 0, []
        span_index = 0
        header_size = {"modbus": 7, "iec104": 2, "s7comm": 4}[protocol]
        while pos < len(data):
            if len(data)-pos < header_size:
                break
            length = 0
            if protocol == "modbus":
                size = int.from_bytes(data[pos+4:pos+6], "big")
                if data[pos+2:pos+4] == b"\x00\x00" and 2 <= size <= 254:
                    length = 6 + size
            elif protocol == "iec104":
                if data[pos] == 0x68 and 4 <= data[pos+1] <= 253:
                    length = 2 + data[pos+1]
            elif data[pos:pos+2] == b"\x03\x00":
                size = int.from_bytes(data[pos+2:pos+4], "big")
                if 7 <= size <= 65535:
                    length = size
            if not length:
                self.stats["unframed_bytes"] += 1
                pos += 1
                continue
            if pos + length > len(data):
                break
            start, end = run.start+pos, run.start+pos+length
            while span_index < len(run.spans) and run.spans[span_index].end <= start:
                span_index += 1
            spans, index = [], span_index
            while index < len(run.spans) and run.spans[index].start < end:
                spans.append(run.spans[index])
                index += 1
            messages.append(Message(protocol, spans[0].packet, bytes(data[pos:pos+length]), spans))
            pos += length
        if final and pos < len(data):
            self.stats["incomplete_regions"] += 1
            self.stats["incomplete_bytes"] += len(data)-pos
            pos = len(data)
        self.stats["messages_reassembled"] += len(messages)
        return messages, pos

import runpy
from pathlib import Path

import pytest


@pytest.fixture
def packets():
    return runpy.run_path(str(Path(__file__).parents[1] / "examples" / "generate_demo_pcaps.py"))


@pytest.fixture
def capture(tmp_path, packets):
    count = 0

    def write(payloads, *, seqs=None, port=502, flags=None):
        nonlocal count
        frames, sequence = [], 1
        for index, payload in enumerate(payloads):
            seq = seqs[index] if seqs is not None else sequence
            flag = flags[index] if flags is not None else 0x18
            frames.append(packets["tcp_frame"]("10.0.0.10", "10.0.0.20", 40000, port,
                                                payload, seq=seq, flags=flag))
            sequence += len(payload)
        path = tmp_path / f"capture-{count}.pcap"
        count += 1
        packets["write_pcap"](path, frames)
        return path

    return write

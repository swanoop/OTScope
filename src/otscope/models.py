from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class TransportPacket:
    timestamp: float
    src: str
    dst: str
    transport: str
    sport: int
    dport: int
    payload: bytes
    wire_len: int
    flags: int = 0


@dataclass
class Asset:
    ip: str
    packets_tx: int = 0
    packets_rx: int = 0
    bytes_tx: int = 0
    bytes_rx: int = 0
    protocols: set[str] = field(default_factory=set)
    service_ports: set[int] = field(default_factory=set)
    roles: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["protocols"] = sorted(self.protocols)
        data["service_ports"] = sorted(self.service_ports)
        data["roles"] = sorted(self.roles)
        return data


@dataclass
class Conversation:
    src: str
    dst: str
    transport: str
    service_port: int
    protocol: str
    packets: int = 0
    bytes: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    semantics: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.src}|{self.dst}|{self.transport}|{self.service_port}|{self.protocol}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        duration = 0.0
        if self.first_seen is not None and self.last_seen is not None:
            duration = max(0.0, self.last_seen - self.first_seen)
        data["key"] = self.key
        data["duration_seconds"] = round(duration, 6)
        data["packet_rate"] = round(self.packets / duration, 6) if duration > 0 else None
        return data


@dataclass
class TimelineEvent:
    timestamp: float
    severity: str
    category: str
    src: str
    dst: str
    protocol: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    severity: str
    kind: str
    title: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

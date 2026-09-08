"""Small, serialisable data types shared by API and capture layers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class ParsedPacket:
    """A protocol-neutral view of one captured frame."""

    timestamp: str
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "OTHER"
    length: int = 0
    tcp_flags: str | None = None
    tcp_seq: int | None = None
    anomalies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_timestamp(epoch: float | None = None) -> str:
    """Return a frontend-safe, timezone-aware timestamp."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat() if epoch else datetime.now(timezone.utc).isoformat()

"""Bounded in-memory store plus query and aggregate helpers."""

from __future__ import annotations

from collections import Counter, deque
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any

from .anomaly import AnomalyDetector
from .models import ParsedPacket


class PacketStore:
    """Keeps exactly the recent capture history required by the dashboard."""

    def __init__(self, capacity: int = 5_000) -> None:
        self.capacity = capacity
        self._packets: deque[ParsedPacket] = deque(maxlen=capacity)
        self._detector = AnomalyDetector()
        self._lock = Lock()

    def add(self, packet: ParsedPacket) -> ParsedPacket:
        with self._lock:
            packet.anomalies = self._detector.inspect(packet)
            self._packets.append(packet)
        return packet

    def packets(self, protocol: str | None = None, ip: str | None = None, port: int | None = None, limit: int = 250) -> list[dict[str, Any]]:
        with self._lock:
            values = list(self._packets)
        values = [packet for packet in values if matches_filter(packet, protocol, ip, port)]
        return [packet.to_dict() for packet in values[-min(max(limit, 1), self.capacity):]][::-1]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            values = list(self._packets)
        now = datetime.now(UTC)
        recent = [packet for packet in values if _packet_time(packet) >= now - timedelta(seconds=1)]
        protocols = Counter(_protocol_bucket(packet.protocol) for packet in values)
        total = len(values)
        talkers = Counter(packet.src_ip for packet in values if packet.src_ip)
        ports = Counter(packet.dst_port for packet in values if packet.dst_port is not None)
        return {
            "captured_packets": total,
            "buffer_capacity": self.capacity,
            "packets_per_second": len(recent),
            "bytes_per_second": sum(packet.length for packet in recent),
            "protocol_distribution": [
                {"protocol": name, "count": count, "percent": round((count / total * 100) if total else 0, 1)}
                for name, count in sorted(protocols.items(), key=lambda item: item[1], reverse=True)
            ],
            "top_talkers": [{"ip": ip, "packets": count} for ip, count in talkers.most_common(5)],
            "top_destination_ports": [{"port": port, "packets": count} for port, count in ports.most_common(5)],
        }


def matches_filter(packet: ParsedPacket, protocol: str | None, ip: str | None, port: int | None) -> bool:
    """Apply live-view filters without affecting capture or stored statistics."""
    if protocol and protocol.upper() != packet.protocol.upper():
        return False
    if ip and ip not in {packet.src_ip, packet.dst_ip}:
        return False
    return not (port is not None and port not in {packet.src_port, packet.dst_port})


def _packet_time(packet: ParsedPacket) -> datetime:
    try:
        return datetime.fromisoformat(packet.timestamp)
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=UTC)


def _protocol_bucket(protocol: str) -> str:
    return protocol if protocol in {"TCP", "UDP", "ICMP"} else "OTHER"

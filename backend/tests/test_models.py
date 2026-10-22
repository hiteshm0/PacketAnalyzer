"""Tests for app.models – ParsedPacket dataclass and utc_timestamp helper."""

from __future__ import annotations

from datetime import UTC, datetime

from app.models import ParsedPacket, utc_timestamp


class TestParsedPacket:
    """Validate ParsedPacket defaults, serialisation, and slots."""

    def test_parsed_packet_defaults(self):
        pkt = ParsedPacket(timestamp="2024-01-01T00:00:00+00:00")
        assert pkt.src_mac is None
        assert pkt.dst_mac is None
        assert pkt.src_ip is None
        assert pkt.dst_ip is None
        assert pkt.src_port is None
        assert pkt.dst_port is None
        assert pkt.protocol == "OTHER"
        assert pkt.length == 0
        assert pkt.tcp_flags is None
        assert pkt.tcp_seq is None
        assert pkt.anomalies == []

    def test_parsed_packet_to_dict(self):
        pkt = ParsedPacket(
            timestamp="2024-01-01T00:00:00+00:00",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol="TCP",
        )
        d = pkt.to_dict()
        assert isinstance(d, dict)
        assert d["src_ip"] == "10.0.0.1"
        assert d["protocol"] == "TCP"

    def test_to_dict_roundtrip(self):
        pkt = ParsedPacket(timestamp="2024-01-01T00:00:00+00:00")
        d = pkt.to_dict()
        expected_keys = {
            "timestamp", "src_mac", "dst_mac", "src_ip", "dst_ip",
            "src_port", "dst_port", "protocol", "length",
            "tcp_flags", "tcp_seq", "anomalies",
        }
        assert set(d.keys()) == expected_keys

    def test_slots_dataclass(self):
        """ParsedPacket uses __slots__ (no __dict__)."""
        pkt = ParsedPacket(timestamp="2024-01-01T00:00:00+00:00")
        assert not hasattr(pkt, "__dict__")


class TestUtcTimestamp:
    def test_utc_timestamp_with_epoch(self):
        epoch = 1700000000.0
        result = utc_timestamp(epoch)
        dt = datetime.fromisoformat(result)
        assert dt == datetime.fromtimestamp(epoch, tz=UTC)

    def test_utc_timestamp_without_epoch(self):
        result = utc_timestamp()
        dt = datetime.fromisoformat(result)
        assert dt.tzinfo is not None
        # Should be very close to now
        diff = abs((datetime.now(UTC) - dt).total_seconds())
        assert diff < 2.0

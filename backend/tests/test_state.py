"""Tests for app.state – PacketStore, matches_filter, and statistics."""

from __future__ import annotations

from app.state import PacketStore, matches_filter


class TestPacketStore:
    """Verify storage, retrieval, filtering, and statistics."""

    def test_add_and_retrieve_packets(self, store, make_parsed_packet):
        """Add packets and query returns them."""
        p1 = make_parsed_packet(src_ip="10.0.0.1")
        p2 = make_parsed_packet(src_ip="10.0.0.2")
        store.add(p1)
        store.add(p2)
        result = store.packets()
        assert len(result) == 2

    def test_ring_buffer_eviction(self, make_parsed_packet):
        """Add more than capacity → oldest evicted."""
        small_store = PacketStore(capacity=5)
        for i in range(10):
            small_store.add(make_parsed_packet(src_ip=f"10.0.0.{i}"))
        result = small_store.packets()
        assert len(result) == 5
        # Most recent packet should be first (newest-first ordering)
        assert result[0]["src_ip"] == "10.0.0.9"

    def test_filter_by_protocol(self, store, make_parsed_packet):
        """Only matching protocol returned."""
        store.add(make_parsed_packet(protocol="TCP"))
        store.add(make_parsed_packet(protocol="UDP", tcp_flags=None, tcp_seq=None))
        store.add(make_parsed_packet(protocol="TCP"))
        result = store.packets(protocol="TCP")
        assert len(result) == 2
        assert all(p["protocol"] == "TCP" for p in result)

    def test_filter_by_ip(self, store, make_parsed_packet):
        """Match on src_ip or dst_ip."""
        store.add(make_parsed_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2"))
        store.add(make_parsed_packet(src_ip="10.0.0.3", dst_ip="10.0.0.4"))
        result = store.packets(ip="10.0.0.1")
        assert len(result) == 1
        # Also match on dst_ip
        result = store.packets(ip="10.0.0.4")
        assert len(result) == 1

    def test_filter_by_port(self, store, make_parsed_packet):
        """Match on src_port or dst_port."""
        store.add(make_parsed_packet(src_port=443, dst_port=12345))
        store.add(make_parsed_packet(src_port=80, dst_port=54321))
        result = store.packets(port=443)
        assert len(result) == 1
        result = store.packets(port=54321)
        assert len(result) == 1

    def test_filter_combined(self, store, make_parsed_packet):
        """Protocol + ip filter together."""
        store.add(make_parsed_packet(protocol="TCP", src_ip="10.0.0.1"))
        store.add(make_parsed_packet(protocol="UDP", src_ip="10.0.0.1", tcp_flags=None, tcp_seq=None))
        store.add(make_parsed_packet(protocol="TCP", src_ip="10.0.0.2"))
        result = store.packets(protocol="TCP", ip="10.0.0.1")
        assert len(result) == 1
        assert result[0]["protocol"] == "TCP"
        assert result[0]["src_ip"] == "10.0.0.1"

    def test_stats_protocol_distribution(self, store, make_parsed_packet):
        """Counts TCP/UDP/ICMP/OTHER correctly."""
        store.add(make_parsed_packet(protocol="TCP"))
        store.add(make_parsed_packet(protocol="TCP"))
        store.add(make_parsed_packet(protocol="UDP", tcp_flags=None, tcp_seq=None))
        store.add(make_parsed_packet(protocol="ICMP", tcp_flags=None, tcp_seq=None))
        stats = store.stats()
        dist = {item["protocol"]: item["count"] for item in stats["protocol_distribution"]}
        assert dist["TCP"] == 2
        assert dist["UDP"] == 1
        assert dist["ICMP"] == 1

    def test_stats_top_talkers(self, store, make_parsed_packet):
        """Most frequent src_ip ranked first."""
        for _ in range(5):
            store.add(make_parsed_packet(src_ip="10.0.0.1"))
        for _ in range(3):
            store.add(make_parsed_packet(src_ip="10.0.0.2"))
        stats = store.stats()
        talkers = stats["top_talkers"]
        assert len(talkers) >= 2
        assert talkers[0]["ip"] == "10.0.0.1"
        assert talkers[0]["packets"] == 5

    def test_stats_empty_store(self):
        """Stats on empty store returns zeros."""
        empty_store = PacketStore(capacity=10)
        stats = empty_store.stats()
        assert stats["captured_packets"] == 0
        assert stats["packets_per_second"] == 0
        assert stats["bytes_per_second"] == 0
        assert stats["protocol_distribution"] == []
        assert stats["top_talkers"] == []

    def test_packets_ordered_newest_first(self, store, make_parsed_packet):
        """Most recent packet first in results."""
        for i in range(5):
            store.add(make_parsed_packet(src_ip=f"10.0.{i}.1"))
        result = store.packets()
        assert result[0]["src_ip"] == "10.0.4.1"
        assert result[-1]["src_ip"] == "10.0.0.1"


class TestMatchesFilter:
    """Verify the standalone matches_filter function."""

    def test_matches_no_filter(self, make_parsed_packet):
        pkt = make_parsed_packet()
        assert matches_filter(pkt, None, None, None) is True

    def test_matches_protocol_case_insensitive(self, make_parsed_packet):
        pkt = make_parsed_packet(protocol="TCP")
        assert matches_filter(pkt, "tcp", None, None) is True

    def test_rejects_wrong_protocol(self, make_parsed_packet):
        pkt = make_parsed_packet(protocol="TCP")
        assert matches_filter(pkt, "UDP", None, None) is False

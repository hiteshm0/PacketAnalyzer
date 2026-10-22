"""Tests for app.parser – layer-by-layer Scapy packet parsing."""

from __future__ import annotations

from datetime import datetime

from scapy.all import IP, TCP, Ether, Raw

from app.parser import parse_packet


class TestParsePacket:
    """Validate that parse_packet correctly extracts fields from Scapy packets."""

    def test_tcp_packet_fields(self, tcp_packet):
        parsed = parse_packet(tcp_packet)
        assert parsed.protocol == "TCP"
        assert parsed.src_ip == "10.0.0.1"
        assert parsed.dst_ip == "10.0.0.2"
        assert parsed.src_port == 12345
        assert parsed.dst_port == 80
        assert parsed.tcp_flags == "S"
        assert parsed.tcp_seq == 1000
        assert parsed.src_mac == "aa:bb:cc:dd:ee:01"
        assert parsed.dst_mac == "aa:bb:cc:dd:ee:02"

    def test_udp_packet_fields(self, udp_packet):
        parsed = parse_packet(udp_packet)
        assert parsed.protocol == "UDP"
        assert parsed.src_ip == "10.0.0.3"
        assert parsed.dst_ip == "10.0.0.4"
        assert parsed.src_port == 5000
        assert parsed.dst_port == 53

    def test_arp_packet_fields(self, arp_packet):
        parsed = parse_packet(arp_packet)
        assert parsed.protocol == "ARP"
        assert parsed.src_ip == "10.0.0.5"
        assert parsed.dst_ip == "10.0.0.6"
        assert parsed.src_port is None
        assert parsed.dst_port is None

    def test_icmp_packet_fields(self, icmp_packet):
        parsed = parse_packet(icmp_packet)
        assert parsed.protocol == "ICMP"
        assert parsed.src_ip == "10.0.0.7"
        assert parsed.dst_ip == "10.0.0.8"
        assert parsed.src_port is None
        assert parsed.dst_port is None

    def test_ipv6_tcp_packet(self, ipv6_tcp_packet):
        parsed = parse_packet(ipv6_tcp_packet)
        assert parsed.src_ip == "2001:db8::1"
        assert parsed.dst_ip == "2001:db8::2"
        assert parsed.protocol == "TCP"
        assert parsed.src_port == 443
        assert parsed.dst_port == 8080

    def test_ethernet_mac_extraction(self, tcp_packet):
        parsed = parse_packet(tcp_packet)
        assert parsed.src_mac == "aa:bb:cc:dd:ee:01"
        assert parsed.dst_mac == "aa:bb:cc:dd:ee:02"

    def test_ip_only_no_transport(self, bare_ip_packet):
        parsed = parse_packet(bare_ip_packet)
        assert parsed.protocol == "OTHER"
        assert parsed.src_ip == "10.0.0.11"
        assert parsed.dst_ip == "10.0.0.12"

    def test_no_ethernet_layer(self):
        """Raw IP packet (no Ether) still parses IP fields."""
        pkt = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=443, flags="A")
        parsed = parse_packet(pkt)
        assert parsed.src_ip == "192.168.1.1"
        assert parsed.dst_ip == "192.168.1.2"
        assert parsed.protocol == "TCP"
        assert parsed.src_mac is None
        assert parsed.dst_mac is None

    def test_malformed_packet_returns_other(self):
        """Raw bytes → protocol OTHER and no crash."""
        pkt = Raw(b"\x00\x01\x02\x03")
        parsed = parse_packet(pkt)
        assert parsed.protocol == "OTHER"

    def test_packet_length_measured(self, tcp_packet):
        parsed = parse_packet(tcp_packet)
        assert parsed.length > 0

    def test_tcp_flags_string(self):
        """Flags like 'S', 'SA', 'A' are stored as strings."""
        for flags_val, expected in [("S", "S"), ("SA", "SA"), ("A", "A")]:
            pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags=flags_val)
            parsed = parse_packet(pkt)
            assert isinstance(parsed.tcp_flags, str)
            assert parsed.tcp_flags == expected

    def test_timestamp_is_iso_format(self, tcp_packet):
        parsed = parse_packet(tcp_packet)
        # Should not raise
        dt = datetime.fromisoformat(parsed.timestamp)
        assert dt.tzinfo is not None  # timezone-aware

"""Shared fixtures for the PacketSniffer test suite."""

from __future__ import annotations

import pytest
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, IPv6

from app.anomaly import AnomalyDetector
from app.models import ParsedPacket, utc_timestamp
from app.state import PacketStore


@pytest.fixture()
def tcp_packet():
    """Ether/IP/TCP with specific src/dst/ports/flags/seq."""
    return (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="S", seq=1000)
    )


@pytest.fixture()
def udp_packet():
    """Ether/IP/UDP packet."""
    return (
        Ether(src="aa:bb:cc:dd:ee:03", dst="aa:bb:cc:dd:ee:04")
        / IP(src="10.0.0.3", dst="10.0.0.4")
        / UDP(sport=5000, dport=53)
    )


@pytest.fixture()
def arp_packet():
    """Ether/ARP packet."""
    return (
        Ether(src="aa:bb:cc:dd:ee:05", dst="ff:ff:ff:ff:ff:ff")
        / ARP(psrc="10.0.0.5", pdst="10.0.0.6")
    )


@pytest.fixture()
def icmp_packet():
    """Ether/IP/ICMP packet."""
    return (
        Ether(src="aa:bb:cc:dd:ee:07", dst="aa:bb:cc:dd:ee:08")
        / IP(src="10.0.0.7", dst="10.0.0.8")
        / ICMP()
    )


@pytest.fixture()
def ipv6_tcp_packet():
    """Ether/IPv6/TCP packet."""
    return (
        Ether(src="aa:bb:cc:dd:ee:09", dst="aa:bb:cc:dd:ee:0a")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=443, dport=8080, flags="SA")
    )


@pytest.fixture()
def bare_ip_packet():
    """Ether/IP with no transport layer."""
    return Ether(src="aa:bb:cc:dd:ee:0b", dst="aa:bb:cc:dd:ee:0c") / IP(src="10.0.0.11", dst="10.0.0.12")


@pytest.fixture()
def store():
    """PacketStore with small capacity for testing."""
    return PacketStore(capacity=100)


@pytest.fixture()
def detector():
    """Fresh AnomalyDetector instance."""
    return AnomalyDetector()


@pytest.fixture()
def make_parsed_packet():
    """Factory fixture that returns a function to create ParsedPacket instances with defaults."""

    def _make(
        *,
        timestamp: str | None = None,
        src_mac: str | None = None,
        dst_mac: str | None = None,
        src_ip: str | None = "10.0.0.1",
        dst_ip: str | None = "10.0.0.2",
        src_port: int | None = 12345,
        dst_port: int | None = 80,
        protocol: str = "TCP",
        length: int = 64,
        tcp_flags: str | None = "S",
        tcp_seq: int | None = 1000,
        anomalies: list[str] | None = None,
    ) -> ParsedPacket:
        return ParsedPacket(
            timestamp=timestamp or utc_timestamp(),
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=length,
            tcp_flags=tcp_flags,
            tcp_seq=tcp_seq,
            anomalies=anomalies if anomalies is not None else [],
        )

    return _make

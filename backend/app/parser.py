"""Defensive, layer-by-layer packet parsing.

Scapy packets may be partial (for example when the NIC snap length is small) or
malformed.  This module intentionally checks each layer before accessing it so a
single bad frame cannot interrupt the capture thread.
"""

from __future__ import annotations

from scapy.all import ARP, Ether, ICMP, IP, IPv6, TCP, UDP
from scapy.packet import Packet

from .models import ParsedPacket, utc_timestamp


def parse_packet(packet: Packet) -> ParsedPacket:
    """Turn a Scapy packet into the fields the dashboard exposes.

    Ethernet is examined first because MAC addresses exist at L2.  ARP is then
    handled independently: it carries network addresses but is not an IP packet.
    Only after an IP/IPv6 layer is present do we inspect the L4 TCP/UDP/ICMP
    layers. This mirrors encapsulation and avoids assumptions about packet shape.
    """
    try:
        parsed = ParsedPacket(timestamp=utc_timestamp(float(getattr(packet, "time", 0) or 0)))
        try:
            parsed.length = len(packet)
        except Exception:
            parsed.length = 0

        if packet.haslayer(Ether):
            ethernet = packet[Ether]
            parsed.src_mac = str(getattr(ethernet, "src", "")) or None
            parsed.dst_mac = str(getattr(ethernet, "dst", "")) or None

        if packet.haslayer(ARP):
            arp = packet[ARP]
            parsed.protocol = "ARP"
            parsed.src_ip = str(getattr(arp, "psrc", "")) or None
            parsed.dst_ip = str(getattr(arp, "pdst", "")) or None
            return parsed

        if packet.haslayer(IP):
            ip = packet[IP]
            parsed.src_ip, parsed.dst_ip = str(ip.src), str(ip.dst)
        elif packet.haslayer(IPv6):
            ip6 = packet[IPv6]
            parsed.src_ip, parsed.dst_ip = str(ip6.src), str(ip6.dst)
        else:
            return parsed

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            parsed.protocol = "TCP"
            parsed.src_port, parsed.dst_port = int(tcp.sport), int(tcp.dport)
            parsed.tcp_flags, parsed.tcp_seq = str(tcp.flags), int(tcp.seq)
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            parsed.protocol = "UDP"
            parsed.src_port, parsed.dst_port = int(udp.sport), int(udp.dport)
        elif packet.haslayer(ICMP):
            parsed.protocol = "ICMP"
        else:
            # It is IP but no L4 type we explicitly support (ESP, GRE, etc.).
            parsed.protocol = "OTHER"
        return parsed
    except Exception:
        # Parsing is deliberately fail-safe. Metadata still makes the bad frame
        # visible to operators instead of silently losing it or killing capture.
        return ParsedPacket(timestamp=utc_timestamp(), protocol="OTHER")

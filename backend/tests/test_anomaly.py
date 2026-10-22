"""Tests for app.anomaly – heuristic anomaly detection."""

from __future__ import annotations

from unittest.mock import patch

from app.anomaly import AnomalyDetector


class TestAnomalyDetector:
    """Verify the three heuristic detectors in AnomalyDetector."""

    def test_no_anomalies_normal_traffic(self, make_parsed_packet):
        """A single TCP packet should produce no alerts."""
        detector = AnomalyDetector()
        pkt = make_parsed_packet(tcp_seq=9999)
        with patch("app.anomaly.monotonic", return_value=100.0):
            alerts = detector.inspect(pkt)
        assert alerts == []

    def test_tcp_retransmission_detected(self, make_parsed_packet):
        """Same 5-tuple + seq within TTL → 'tcp_retransmission'."""
        detector = AnomalyDetector()
        pkt = make_parsed_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, tcp_seq=5000,
        )
        with patch("app.anomaly.monotonic", return_value=100.0):
            detector.inspect(pkt)
        with patch("app.anomaly.monotonic", return_value=101.0):
            alerts = detector.inspect(pkt)
        assert "tcp_retransmission" in alerts

    def test_retransmission_different_direction_no_alert(self, make_parsed_packet):
        """Swapped src/dst → no retransmission alert."""
        detector = AnomalyDetector()
        pkt1 = make_parsed_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, tcp_seq=5000,
        )
        pkt2 = make_parsed_packet(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=12345, tcp_seq=5000,
        )
        with patch("app.anomaly.monotonic", return_value=100.0):
            detector.inspect(pkt1)
        with patch("app.anomaly.monotonic", return_value=101.0):
            alerts = detector.inspect(pkt2)
        assert "tcp_retransmission" not in alerts

    def test_retransmission_expires_after_ttl(self, make_parsed_packet):
        """After 120s gap → no retransmission alert."""
        detector = AnomalyDetector()
        pkt = make_parsed_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, tcp_seq=5000,
        )
        with patch("app.anomaly.monotonic", return_value=100.0):
            detector.inspect(pkt)
        # 121 seconds later: beyond the 120s TTL
        with patch("app.anomaly.monotonic", return_value=221.0):
            alerts = detector.inspect(pkt)
        assert "tcp_retransmission" not in alerts

    def test_syn_burst_at_threshold(self, make_parsed_packet):
        """Exactly 20 SYN-no-ACK packets within the window → 'syn_burst'."""
        detector = AnomalyDetector()
        found_syn_burst = False
        with patch("app.anomaly.monotonic", return_value=100.0):
            for i in range(20):
                pkt = make_parsed_packet(
                    src_ip="10.0.0.1", dst_ip=f"10.0.1.{i}",
                    src_port=12345, dst_port=80,
                    tcp_flags="S", tcp_seq=i,
                )
                alerts = detector.inspect(pkt)
                if "syn_burst" in alerts:
                    found_syn_burst = True
        assert found_syn_burst

    def test_syn_burst_below_threshold(self, make_parsed_packet):
        """19 SYN packets → no syn_burst."""
        detector = AnomalyDetector()
        all_alerts: list[str] = []
        with patch("app.anomaly.monotonic", return_value=100.0):
            for i in range(19):
                pkt = make_parsed_packet(
                    src_ip="10.0.0.1", dst_ip=f"10.0.1.{i}",
                    src_port=12345, dst_port=80,
                    tcp_flags="S", tcp_seq=i,
                )
                all_alerts.extend(detector.inspect(pkt))
        assert "syn_burst" not in all_alerts

    def test_syn_established_ignored(self, make_parsed_packet):
        """SYN+ACK packets don't count toward syn_burst."""
        detector = AnomalyDetector()
        all_alerts: list[str] = []
        with patch("app.anomaly.monotonic", return_value=100.0):
            for i in range(25):
                pkt = make_parsed_packet(
                    src_ip="10.0.0.1", dst_ip=f"10.0.1.{i}",
                    src_port=12345, dst_port=80,
                    tcp_flags="SA", tcp_seq=i,
                )
                all_alerts.extend(detector.inspect(pkt))
        assert "syn_burst" not in all_alerts

    def test_unusual_source_rate_triggered(self, make_parsed_packet):
        """50+ packets from one source, 5x average → 'unusual_source_rate'."""
        detector = AnomalyDetector()
        found_rate_alert = False
        with patch("app.anomaly.monotonic", return_value=100.0):
            # 5 background sources with 1 packet each to establish low average
            for s in range(5):
                detector.inspect(
                    make_parsed_packet(
                        src_ip=f"192.168.1.{s+10}", dst_ip="10.0.0.2",
                        src_port=12345, dst_port=80,
                        tcp_flags="A", tcp_seq=1,
                    )
                )
            for i in range(55):
                pkt = make_parsed_packet(
                    src_ip="10.0.0.1", dst_ip="10.0.0.2",
                    src_port=12345, dst_port=80,
                    tcp_flags="A", tcp_seq=i,
                )
                alerts = detector.inspect(pkt)
                if "unusual_source_rate" in alerts:
                    found_rate_alert = True
        assert found_rate_alert

    def test_unusual_source_rate_below_threshold(self, make_parsed_packet):
        """49 packets → no unusual_source_rate."""
        detector = AnomalyDetector()
        all_alerts: list[str] = []
        with patch("app.anomaly.monotonic", return_value=100.0):
            for s in range(5):
                detector.inspect(
                    make_parsed_packet(
                        src_ip=f"192.168.1.{s+10}", dst_ip="10.0.0.2",
                        src_port=12345, dst_port=80,
                        tcp_flags="A", tcp_seq=1,
                    )
                )
            for i in range(49):
                pkt = make_parsed_packet(
                    src_ip="10.0.0.1", dst_ip="10.0.0.2",
                    src_port=12345, dst_port=80,
                    tcp_flags="A", tcp_seq=i,
                )
                all_alerts.extend(detector.inspect(pkt))
        assert "unusual_source_rate" not in all_alerts

    def test_mixed_traffic_multiple_anomalies(self, make_parsed_packet):
        """Can fire multiple alerts on same packet (retransmission + rate)."""
        detector = AnomalyDetector()
        pkt = make_parsed_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80,
            tcp_flags="A", tcp_seq=42,
        )
        with patch("app.anomaly.monotonic", return_value=100.0):
            # Background sources
            for s in range(5):
                detector.inspect(
                    make_parsed_packet(
                        src_ip=f"192.168.1.{s+10}", dst_ip="10.0.0.2",
                        src_port=12345, dst_port=80,
                        tcp_flags="A", tcp_seq=1,
                    )
                )
            # Send 50 packets to reach threshold
            for i in range(50):
                detector.inspect(
                    make_parsed_packet(
                        src_ip="10.0.0.1", dst_ip="10.0.0.2",
                        src_port=12345, dst_port=80,
                        tcp_flags="A", tcp_seq=i + 1000,
                    )
                )
            # First time with seq=42
            detector.inspect(pkt)
            # Second time with seq=42 → retransmission + unusual_source_rate
            alerts = detector.inspect(pkt)
        assert "tcp_retransmission" in alerts
        assert "unusual_source_rate" in alerts

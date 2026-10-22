"""Tests for app.capture – capture lifecycle and interface discovery."""

from __future__ import annotations

from queue import Queue
from unittest.mock import MagicMock, patch

import pytest
from scapy.all import IP, TCP, Ether

from app.capture import CaptureController, default_interface, interfaces
from app.models import ParsedPacket


class TestInterfaces:
    def test_interfaces_returns_list(self):
        result = interfaces()
        assert isinstance(result, list)

    def test_interfaces_handles_exception(self):
        with patch("app.capture.get_if_list", side_effect=RuntimeError("no ifaces")):
            assert interfaces() == []

    def test_default_interface_selects_non_loopback(self):
        with patch("app.capture.interfaces", return_value=["lo0", "en0", "en1"]):
            assert default_interface() == "en0"

    def test_default_interface_fallback_to_loopback(self):
        with patch("app.capture.interfaces", return_value=["lo0"]):
            assert default_interface() == "lo0"

    def test_default_interface_empty(self):
        with patch("app.capture.interfaces", return_value=[]):
            assert default_interface() is None


class TestCaptureController:
    def test_start_already_running(self):
        q: Queue[ParsedPacket] = Queue()
        controller = CaptureController(q)
        controller._thread = MagicMock(is_alive=lambda: True)
        controller.interface = "en0"

        chosen = controller.start("en0")
        assert chosen == "en0"

    def test_start_no_interface_raises(self):
        q: Queue[ParsedPacket] = Queue()
        controller = CaptureController(q)
        with patch("app.capture.interfaces", return_value=[]), \
             patch("app.capture.default_interface", return_value=None), \
             pytest.raises(RuntimeError, match="No capture interfaces found"):
            controller.start()

    def test_start_unknown_interface_raises(self):
        q: Queue[ParsedPacket] = Queue()
        controller = CaptureController(q)
        with patch("app.capture.interfaces", return_value=["en0"]), \
             pytest.raises(ValueError, match="Unknown interface"):
            controller.start("nonexistent0")

    def test_on_packet_puts_in_queue(self):
        q: Queue[ParsedPacket] = Queue(maxsize=10)
        controller = CaptureController(q)
        raw = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=123, dport=80)

        controller._on_packet(raw)
        assert not q.empty()
        pkt = q.get_nowait()
        assert pkt.src_ip == "10.0.0.1"

    def test_on_packet_handles_queue_full(self):
        q: Queue[ParsedPacket] = Queue(maxsize=1)
        controller = CaptureController(q)
        raw = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=123, dport=80)

        # Fill queue
        controller._on_packet(raw)
        assert q.full()

        # Second put should drop gracefully without exception
        controller._on_packet(raw)
        assert q.qsize() == 1

    def test_on_packet_handles_exception_gracefully(self):
        q: Queue[ParsedPacket] = Queue()
        controller = CaptureController(q)
        with patch("app.capture.parse_packet", side_effect=RuntimeError("parse boom")):
            # Should not raise
            controller._on_packet("not a packet")

    def test_stop_joins_thread(self):
        q: Queue[ParsedPacket] = Queue()
        controller = CaptureController(q)
        mock_thread = MagicMock()
        controller._thread = mock_thread

        controller.stop()
        assert controller._stop_event.is_set()
        mock_thread.join.assert_called_once_with(timeout=2)

    def test_run_catches_sniff_exception(self):
        q: Queue[ParsedPacket] = Queue()
        controller = CaptureController(q)
        controller.interface = "en0"

        with patch("app.capture.sniff", side_effect=PermissionError("Need root")):
            controller._run()

        assert controller.error is not None
        assert "Need root" in controller.error
        assert controller._stop_event.is_set()

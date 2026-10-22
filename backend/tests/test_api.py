"""Tests for app.main – FastAPI REST endpoints and WebSocket."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


class TestHealthEndpoint:
    def test_health_endpoint(self):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "capture_running" in data


class TestInterfacesEndpoint:
    def test_interfaces_endpoint(self):
        resp = client.get("/api/interfaces")
        assert resp.status_code == 200
        data = resp.json()
        assert "interfaces" in data
        assert isinstance(data["interfaces"], list)


class TestStatsEndpoint:
    def test_stats_endpoint(self):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        for key in ("captured_packets", "buffer_capacity", "packets_per_second", "protocol_distribution", "top_talkers"):
            assert key in data


class TestPacketsEndpoint:
    def test_packets_endpoint_empty(self):
        resp = client.get("/api/packets")
        assert resp.status_code == 200
        data = resp.json()
        assert "packets" in data
        assert isinstance(data["packets"], list)

    def test_packets_with_protocol_filter(self):
        resp = client.get("/api/packets", params={"protocol": "TCP"})
        assert resp.status_code == 200
        assert "packets" in resp.json()

    def test_packets_with_port_filter(self):
        resp = client.get("/api/packets", params={"port": 443})
        assert resp.status_code == 200
        assert "packets" in resp.json()

    def test_packets_invalid_port(self):
        resp = client.get("/api/packets", params={"port": 99999})
        assert resp.status_code == 422


class TestCaptureEndpoints:
    def test_capture_start_unknown_interface(self):
        resp = client.post("/api/capture/start", json={"interface": "nonexistent_iface_xyz"})
        assert resp.status_code == 400

    def test_capture_stop(self):
        resp = client.post("/api/capture/stop")
        assert resp.status_code == 200
        data = resp.json()
        assert data["running"] is False


class TestWebSocket:
    def test_websocket_connection(self):
        with client.websocket_connect("/ws/packets") as ws:
            data = ws.receive_json()
            assert data == {"type": "connected"}

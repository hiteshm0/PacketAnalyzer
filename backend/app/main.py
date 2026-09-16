"""FastAPI boundary for controls, history, statistics, and live WebSocket data."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from queue import Empty, Queue
from typing import Any

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .capture import CaptureController, default_interface, interfaces
from .models import ParsedPacket
from .state import PacketStore, matches_filter


class StartCapture(BaseModel):
    interface: str | None = None


class ClientFilter(BaseModel):
    protocol: str | None = None
    ip: str | None = None
    port: int | None = None


class Hub:
    """WebSocket connections own their own display filter."""
    def __init__(self) -> None:
        self.clients: dict[WebSocket, ClientFilter] = {}

    async def broadcast(self, packet: ParsedPacket) -> None:
        for socket, filter_ in list(self.clients.items()):
            if not matches_filter(packet, filter_.protocol, filter_.ip, filter_.port):
                continue
            try:
                await socket.send_json({"type": "packet", "packet": packet.to_dict()})
            except Exception:
                self.clients.pop(socket, None)


# This is bounded too: an overloaded WebSocket/API loop must not allow an
# unbounded backlog even though the retained history itself is capped.
packet_queue: Queue[ParsedPacket] = Queue(maxsize=10_000)
store = PacketStore(capacity=5_000)
capture = CaptureController(packet_queue)
hub = Hub()


async def dispatch_packets() -> None:
    """Bridge the thread-safe Scapy queue into FastAPI's async WebSocket world."""
    while True:
        # A timeout keeps shutdown deterministic: a worker otherwise remains
        # blocked forever in Queue.get() if no packets arrive during shutdown.
        try:
            packet = await asyncio.to_thread(packet_queue.get, True, 0.5)
        except Empty:
            continue
        stored = store.add(packet)
        await hub.broadcast(stored)


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(dispatch_packets())
    yield
    capture.stop()
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task


app = FastAPI(title="Network Traffic Analyzer", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "capture_running": capture.running, "capture_error": capture.error}


@app.get("/api/interfaces")
def list_interfaces() -> dict[str, Any]:
    return {"interfaces": interfaces(), "default": default_interface()}


@app.post("/api/capture/start")
def start_capture(request: StartCapture) -> dict[str, Any]:
    try:
        chosen = capture.start(request.interface)
        return {"running": True, "interface": chosen}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/capture/stop")
def stop_capture() -> dict[str, Any]:
    capture.stop()
    return {"running": False}


@app.get("/api/packets")
def get_packets(
    protocol: str | None = None,
    ip: str | None = None,
    port: int | None = Query(default=None, ge=0, le=65535),
    limit: int = Query(default=250, ge=1, le=5_000),
) -> dict[str, Any]:
    return {"packets": store.packets(protocol, ip, port, limit)}


@app.get("/api/stats")
def get_stats() -> dict[str, Any]:
    result = store.stats()
    result.update({"capture_running": capture.running, "interface": capture.interface, "capture_error": capture.error})
    return result


@app.websocket("/ws/packets")
async def packets_socket(socket: WebSocket) -> None:
    await socket.accept()
    hub.clients[socket] = ClientFilter()
    try:
        await socket.send_json({"type": "connected"})
        while True:
            message = await socket.receive_json()
            if message.get("type") == "filter":
                hub.clients[socket] = ClientFilter(**message.get("filter", {}))
    except WebSocketDisconnect:
        pass
    finally:
        hub.clients.pop(socket, None)

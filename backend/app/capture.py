"""Scapy capture adapter, isolated from web and statistics concerns."""

from __future__ import annotations

from queue import Full, Queue
from threading import Event, Lock, Thread

from scapy.all import get_if_list, sniff

from .parser import parse_packet
from .models import ParsedPacket


def interfaces() -> list[str]:
    """Best-effort interface discovery; Scapy delegates OS-specific details."""
    try:
        return list(get_if_list())
    except Exception:
        return []


def default_interface() -> str | None:
    """Prefer a non-loopback interface, while retaining a safe fallback."""
    available = interfaces()
    for name in available:
        if name.lower() not in {"lo", "lo0", "loopback"}:
            return name
    return available[0] if available else None


class CaptureController:
    """Owns Scapy's blocking loop and writes parsed packets to a safe queue."""

    def __init__(self, output: Queue[ParsedPacket]) -> None:
        self._output = output
        self._stop_event = Event()
        self._lock = Lock()
        self._thread: Thread | None = None
        self.interface: str | None = None
        self.error: str | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, interface: str | None = None) -> str:
        with self._lock:
            if self.running:
                return self.interface or ""
            chosen = interface or default_interface()
            if not chosen:
                raise RuntimeError("No capture interfaces found")
            if chosen not in interfaces():
                raise ValueError(f"Unknown interface: {chosen}")
            self.interface, self.error = chosen, None
            self._stop_event.clear()
            self._thread = Thread(target=self._run, name="scapy-capture", daemon=True)
            self._thread.start()
            return chosen

    def stop(self) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread:
            thread.join(timeout=2)

    def _run(self) -> None:
        # sniff() blocks. A short timeout lets us check the stop event while
        # keeping packet callbacks inside this dedicated background thread.
        try:
            while not self._stop_event.is_set():
                sniff(iface=self.interface, prn=self._on_packet, store=False, timeout=1)
        except Exception as exc:
            self.error = f"Capture stopped: {exc}"
        finally:
            self._stop_event.set()

    def _on_packet(self, packet: object) -> None:
        try:
            self._output.put_nowait(parse_packet(packet))  # type: ignore[arg-type]
        except Full:
            # Under sustained overload retain liveness over completeness; the
            # dashboard is a live analyzer, and its bounded history would evict
            # these oldest queued records shortly anyway.
            return
        except Exception:
            # Never let a parser or queue edge case propagate into Scapy's loop.
            return

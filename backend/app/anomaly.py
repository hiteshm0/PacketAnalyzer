"""Small, transparent heuristics for highlighting traffic worth inspecting."""

from __future__ import annotations

from collections import defaultdict, deque
from time import monotonic

from .models import ParsedPacket


class AnomalyDetector:
    """Stateful heuristic detector; alerts are clues, not security verdicts."""

    RETRANSMIT_TTL_SECONDS = 120
    SYN_WINDOW_SECONDS = 10
    SYN_BURST_THRESHOLD = 20
    RATE_WINDOW_SECONDS = 10
    RATE_MIN_PACKETS = 50

    def __init__(self) -> None:
        self._seen_sequences: dict[tuple[str, str, int, int, int], float] = {}
        self._syn_times: dict[str, deque[float]] = defaultdict(deque)
        self._source_times: dict[str, deque[float]] = defaultdict(deque)

    def inspect(self, packet: ParsedPacket) -> list[str]:
        """Return labels for basic retransmit and unusually concentrated traffic.

        A repeated TCP sequence number for the same directional four-tuple in a
        short TTL is treated as a retransmission. This is intentionally simple:
        sequence reuse can also appear in captures with duplicates or after a
        connection is recycled, so it is an investigation signal, not proof.

        The traffic heuristic flags a source only when it sends at least 50
        packets in ten seconds *and* is five times the average per active source.
        SYN bursts are independently flagged at 20 SYN-without-ACK packets in ten
        seconds. NATs, busy services, and legitimate scans can trigger either.
        """
        now = monotonic()
        alerts: list[str] = []
        self._prune(now)

        if packet.protocol == "TCP" and packet.tcp_seq is not None and packet.src_ip and packet.dst_ip:
            key = (packet.src_ip, packet.dst_ip, packet.src_port or 0, packet.dst_port or 0, packet.tcp_seq)
            if key in self._seen_sequences:
                alerts.append("tcp_retransmission")
            self._seen_sequences[key] = now

        if not packet.src_ip:
            return alerts
        source_events = self._source_times[packet.src_ip]
        source_events.append(now)
        active = [events for events in self._source_times.values() if events]
        average = sum(len(events) for events in active) / max(len(active), 1)
        if len(source_events) >= self.RATE_MIN_PACKETS and len(source_events) >= max(5 * average, self.RATE_MIN_PACKETS):
            alerts.append("unusual_source_rate")

        # SYN without ACK is the useful half-open/scan indicator; established
        # connection packets with ACK are excluded to reduce false positives.
        if packet.protocol == "TCP" and packet.tcp_flags and "S" in packet.tcp_flags and "A" not in packet.tcp_flags:
            syns = self._syn_times[packet.src_ip]
            syns.append(now)
            if len(syns) >= self.SYN_BURST_THRESHOLD:
                alerts.append("syn_burst")
        return alerts

    def _prune(self, now: float) -> None:
        self._seen_sequences = {key: at for key, at in self._seen_sequences.items() if now - at <= self.RETRANSMIT_TTL_SECONDS}
        for collection, window in ((self._syn_times, self.SYN_WINDOW_SECONDS), (self._source_times, self.RATE_WINDOW_SECONDS)):
            for source in list(collection):
                events = collection[source]
                while events and now - events[0] > window:
                    events.popleft()
                if not events:
                    del collection[source]

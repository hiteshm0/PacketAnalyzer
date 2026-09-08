# Network Traffic Analyzer / Packet Sniffer

A portfolio-sized packet analyzer that captures live frames with Scapy, parses them layer by layer, calculates in-memory traffic statistics, highlights a few explainable anomalies, and streams the results over WebSockets to a minimal React dashboard.

The project deliberately favors inspectable networking internals over dashboard polish. It has no database: the most recent 5,000 packets stay in a bounded ring buffer, and the hand-off queue between capture and API is also bounded.

## Architecture

```text
Scapy sniff() thread
        │ raw packet
        ▼
parser.py (Ethernet → ARP/IP → TCP/UDP/ICMP)
        │ ParsedPacket through bounded Queue
        ▼
FastAPI dispatcher → state.py (5,000-packet ring buffer + statistics + anomaly.py)
        │
        ├── REST: controls, interfaces, history, aggregate statistics
        └── WebSocket: filtered live packet events
                │
                ▼
          React / Vite dashboard
```

The key backend modules are:

- `backend/app/capture.py`: the background-thread Scapy capture adapter.
- `backend/app/parser.py`: defensive layered protocol parsing.
- `backend/app/state.py`: bounded history, filters, and aggregate counters.
- `backend/app/anomaly.py`: deliberately small, documented heuristics.
- `backend/app/main.py`: FastAPI REST and WebSocket boundary.

## Prerequisites

- Python 3.11 or newer
- Node.js 18 or newer and npm
- macOS or Linux. Packet capture needs OS raw-socket/BPF permission.

## Setup and run

From the repository root:

```bash
python3 -m venv backend/venv
source backend/venv/bin/activate
python -m pip install --upgrade pip
pip install -r backend/requirements.txt

cd frontend
npm install
cd ..
```

Start the frontend in one terminal:

```bash
cd frontend
npm run dev
```

Start the backend in a second terminal. The `sudo` command must name the venv interpreter explicitly; otherwise `sudo` uses the system Python and cannot see Scapy/FastAPI installed in the virtual environment:

```bash
sudo backend/venv/bin/python3 backend/main.py
```

Then open the Vite URL (normally `http://localhost:5173`), select an interface, and click **Start capture**. The API itself is at `http://127.0.0.1:8000`; its OpenAPI docs are at `/docs`.

To run without capture privileges for API/UI development, omit `sudo`; interface listing may work but starting a capture will usually fail.

### Why elevated permissions are required

Scapy opens a raw packet socket (Linux) or BPF device (macOS) to receive frames before the operating system delivers them to applications. Those are privileged operations by default. `sudo backend/venv/bin/python3 backend/main.py` is the simplest local-development option. Do not run this dashboard exposed on an untrusted network: its capture controls have no authentication.

On Linux, an alternative is to grant the Python executable `CAP_NET_RAW`/`CAP_NET_ADMIN`, but this is a system security decision and `sudo` is clearer for a portfolio demo. On macOS, packet capture access is generally obtained via administrator privileges/BPF device permissions.

## Defaults and API

- Default interface: first non-loopback name returned by Scapy; choose another in the UI if it is not the active adapter.
- Packet history: last 5,000 parsed packets; old frames are automatically evicted.
- Live table: last 250 packets matching its filter, to keep browser rendering cheap.
- Start/stop endpoints: `POST /api/capture/start` with optional JSON `{ "interface": "en0" }`, and `POST /api/capture/stop`.
- `GET /api/interfaces`, `GET /api/packets?protocol=TCP&ip=...&port=443`, `GET /api/stats`.
- Live stream: `ws://127.0.0.1:8000/ws/packets`. Send `{ "type": "filter", "filter": { "protocol": "TCP", "ip": null, "port": 443 } }` to change only that client's view; capture continues unchanged.

## Parsing approach

`parser.py` checks packet layers in their encapsulation order: Ethernet provides MAC addresses, ARP is treated as its own L2/L3-adjacent protocol, then IPv4/IPv6 provides network addresses, followed by TCP/UDP/ICMP for transport fields. Every layer access is guarded and the public parser catches unexpected Scapy errors, so malformed or truncated traffic turns into an `OTHER` record instead of breaking the capture loop.

## Anomaly heuristics and limitations

`anomaly.py` is intentionally isolated so its choices are easy to discuss:

- **TCP retransmission:** a TCP packet with an already-seen sequence number for the same directional source/destination IP and port tuple within 120 seconds is labelled `tcp_retransmission`.
- **Unusual source rate:** a source must send at least 50 packets in a rolling 10-second window and at least five times the average traffic per active source to be labelled `unusual_source_rate`.
- **SYN burst:** 20 or more SYN-without-ACK packets from one source in a rolling 10-second window are labelled `syn_burst`, a lightweight scan/half-open connection signal.

These are triage signals, not IDS-grade detections. Packet duplication, NAT, busy legitimate services, lost packets, TCP connection reuse, and legitimate scanning can cause false positives. Conversely, thresholds can miss slow scans or distributed activity. In production, use flow reassembly, baselining by host/service/time of day, and alert-rate controls.

## Trade-offs

The capture loop uses Scapy `sniff(..., timeout=1)` inside a dedicated daemon thread. The short timeout is a practical stop mechanism for Scapy's otherwise blocking `sniff()` call. Parsing before the queue keeps web code independent from raw Scapy packets. The in-memory bounded design is ideal for a live interview demo but does not provide persistence, multi-process sharing, packet payload inspection, BPF filtering, or authenticated multi-user access.

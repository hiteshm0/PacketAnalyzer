import { useEffect, useRef, useState } from 'react'

const MAX_ROWS = 250

type Packet = { timestamp: string; src_mac?: string; dst_mac?: string; src_ip?: string; dst_ip?: string; src_port?: number; dst_port?: number; protocol: string; length: number; tcp_flags?: string; anomalies: string[] }
type Stats = { captured_packets: number; buffer_capacity: number; packets_per_second: number; bytes_per_second: number; capture_running: boolean; interface?: string; capture_error?: string; protocol_distribution: { protocol: string; count: number; percent: number }[]; top_talkers: { ip: string; packets: number }[]; top_destination_ports: { port: number; packets: number }[] }
type Filters = { protocol: string; ip: string; port: string }

const emptyStats: Stats = { captured_packets: 0, buffer_capacity: 5000, packets_per_second: 0, bytes_per_second: 0, capture_running: false, protocol_distribution: [], top_talkers: [], top_destination_ports: [] }

export default function App() {
  const [interfaces, setInterfaces] = useState<string[]>([])
  const [selectedInterface, setSelectedInterface] = useState('')
  const [stats, setStats] = useState<Stats>(emptyStats)
  const [packets, setPackets] = useState<Packet[]>([])
  const [filters, setFilters] = useState<Filters>({ protocol: '', ip: '', port: '' })
  const [error, setError] = useState('')
  const socket = useRef<WebSocket | null>(null)

  const refreshStats = async () => {
    try { setStats(await (await fetch(`/api/stats`)).json()) } catch { setError('Backend unavailable. Start the FastAPI server first.') }
  }
  useEffect(() => {
    fetch(`/api/interfaces`).then(r => r.json()).then(data => { setInterfaces(data.interfaces); setSelectedInterface(data.default || '') }).catch(() => setError('Could not load interfaces.'))
    refreshStats(); const timer = window.setInterval(refreshStats, 1000); return () => window.clearInterval(timer)
  }, [])
  useEffect(() => {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${wsProtocol}//${window.location.host}/ws/packets`); socket.current = ws
    ws.onmessage = event => { const message = JSON.parse(event.data); if (message.type === 'packet') setPackets(rows => [message.packet, ...rows].slice(0, MAX_ROWS)) }
    ws.onerror = () => setError('Live connection interrupted.')
    return () => ws.close()
  }, [])
  useEffect(() => {
    if (socket.current?.readyState === WebSocket.OPEN) { try { socket.current.send(JSON.stringify({ type: 'filter', filter: { protocol: filters.protocol || null, ip: filters.ip || null, port: filters.port ? Number(filters.port) : null } })) } catch { /* ignored */ } }
    const params = new URLSearchParams(); if (filters.protocol) params.set('protocol', filters.protocol); if (filters.ip) params.set('ip', filters.ip); if (filters.port) params.set('port', filters.port)
    fetch(`/api/packets?${params}`).then(r => r.json()).then(data => setPackets(data.packets)).catch(() => undefined)
  }, [filters])

  async function control(action: 'start' | 'stop') {
    setError('')
    const response = await fetch(`/api/capture/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: action === 'start' ? JSON.stringify({ interface: selectedInterface || null }) : undefined })
    if (!response.ok) { const data = await response.json(); setError(data.detail || 'Capture control failed.') }
    await refreshStats()
  }
  const changeFilter = (key: keyof Filters, value: string) => setFilters(current => ({ ...current, [key]: value }))

  return <main>
    <header><div><h1>Network Traffic Analyzer</h1><p>Live packet capture and parsing</p></div><div className={stats.capture_running ? 'status running' : 'status'}>{stats.capture_running ? `Capturing: ${stats.interface}` : 'Stopped'}</div></header>
    {error && <p className="error">{error}</p>}
    <section className="controls"><select value={selectedInterface} onChange={e => setSelectedInterface(e.target.value)}>{interfaces.map(name => <option key={name}>{name}</option>)}</select><button onClick={() => control('start')} disabled={stats.capture_running}>Start capture</button><button className="secondary" onClick={() => control('stop')} disabled={!stats.capture_running}>Stop</button></section>
    <section className="cards"><Metric label="Packets/sec" value={stats.packets_per_second} /><Metric label="Bytes/sec" value={formatBytes(stats.bytes_per_second)} /><Metric label="Ring buffer" value={`${stats.captured_packets} / ${stats.buffer_capacity}`} /><Metric label="Top talker" value={stats.top_talkers[0]?.ip || '—'} /></section>
    <section className="summary"><Distribution title="Protocols" items={stats.protocol_distribution.map(x => `${x.protocol}: ${x.percent}%`)} /><Distribution title="Top destination ports" items={stats.top_destination_ports.map(x => `${x.port}: ${x.packets}`)} /><Distribution title="Top talkers" items={stats.top_talkers.map(x => `${x.ip}: ${x.packets}`)} /></section>
    <section className="filters"><label>Protocol<select value={filters.protocol} onChange={e => changeFilter('protocol', e.target.value)}><option value="">All</option>{['TCP', 'UDP', 'ICMP', 'ARP', 'OTHER'].map(x => <option key={x}>{x}</option>)}</select></label><label>IP<input placeholder="Source or destination" value={filters.ip} onChange={e => changeFilter('ip', e.target.value)} /></label><label>Port<input type="number" min="0" max="65535" placeholder="Source or destination" value={filters.port} onChange={e => changeFilter('port', e.target.value)} /></label></section>
    <section className="table-wrap"><table><thead><tr><th>Time</th><th>Protocol</th><th>Source</th><th>Destination</th><th>MAC source → destination</th><th>Length</th><th>Flags / alerts</th></tr></thead><tbody>{packets.map((packet, i) => <tr key={`${packet.timestamp}-${i}`}><td>{new Date(packet.timestamp).toLocaleTimeString()}</td><td><span className={`protocol ${packet.protocol.toLowerCase()}`}>{packet.protocol}</span></td><td>{endpoint(packet.src_ip, packet.src_port)}</td><td>{endpoint(packet.dst_ip, packet.dst_port)}</td><td className="mac">{packet.src_mac || '—'} → {packet.dst_mac || '—'}</td><td>{packet.length}</td><td>{[packet.tcp_flags, ...packet.anomalies].filter(Boolean).join(' · ') || '—'}</td></tr>)}</tbody></table>{!packets.length && <p className="empty">No matching packets yet.</p>}</section>
  </main>
}

function Metric({ label, value }: { label: string; value: string | number }) { return <article className="metric"><span>{label}</span><strong>{value}</strong></article> }
function Distribution({ title, items }: { title: string; items: string[] }) { return <article><h2>{title}</h2>{items.length ? <ul>{items.map(item => <li key={item}>{item}</li>)}</ul> : <p>Waiting for traffic</p>}</article> }
function endpoint(ip?: string, port?: number) { return ip ? `${ip}${port !== undefined ? `:${port}` : ''}` : '—' }
function formatBytes(bytes: number) { return bytes > 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : bytes > 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B` }

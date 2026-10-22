import { Gauge, Download, HardDrive, Users } from 'lucide-react'
import { formatBytes } from '../utils/format'
import type { Stats } from '../types'

interface MetricCardsProps {
  stats: Stats
}

export function MetricCards({ stats }: MetricCardsProps) {
  const bufferPercent = stats.buffer_capacity > 0
    ? Math.round((stats.captured_packets / stats.buffer_capacity) * 100)
    : 0

  return (
    <section className="cards">
      <article className="metric">
        <div className="metric-header">
          <Gauge size={16} className="metric-icon" />
          <span>Packets/sec</span>
        </div>
        <strong>{stats.packets_per_second}</strong>
      </article>

      <article className="metric">
        <div className="metric-header">
          <Download size={16} className="metric-icon" />
          <span>Bytes/sec</span>
        </div>
        <strong>{formatBytes(stats.bytes_per_second)}</strong>
      </article>

      <article className="metric">
        <div className="metric-header">
          <HardDrive size={16} className="metric-icon" />
          <span>Ring buffer</span>
        </div>
        <strong>{stats.captured_packets} / {stats.buffer_capacity}</strong>
        <div className="buffer-bar">
          <div
            className="buffer-fill"
            style={{ width: `${Math.min(bufferPercent, 100)}%` }}
          />
        </div>
        <span className="buffer-percent">{bufferPercent}%</span>
      </article>

      <article className="metric">
        <div className="metric-header">
          <Users size={16} className="metric-icon" />
          <span>Top talker</span>
        </div>
        <strong>{stats.top_talkers[0]?.ip || '—'}</strong>
      </article>
    </section>
  )
}

import { useState } from 'react'
import { formatTimestamp, endpoint } from '../utils/format'
import type { Packet } from '../types'

interface PacketTableProps {
  packets: Packet[]
}

export function PacketTable({ packets }: PacketTableProps) {
  const [expandedRow, setExpandedRow] = useState<number | null>(null)

  const toggleRow = (index: number) => {
    setExpandedRow(prev => (prev === index ? null : index))
  }

  return (
    <section className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Protocol</th>
            <th>Source</th>
            <th>Destination</th>
            <th>MAC source → destination</th>
            <th>Length</th>
            <th>Flags / alerts</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((packet, i) => {
            const hasAnomaly = packet.anomalies.length > 0
            const isExpanded = expandedRow === i
            return (
              <PacketRow
                key={`${packet.timestamp}-${i}`}
                packet={packet}
                hasAnomaly={hasAnomaly}
                isExpanded={isExpanded}
                onClick={() => toggleRow(i)}
              />
            )
          })}
        </tbody>
      </table>
      {!packets.length && <p className="empty">No matching packets yet.</p>}
    </section>
  )
}

interface PacketRowProps {
  packet: Packet
  hasAnomaly: boolean
  isExpanded: boolean
  onClick: () => void
}

function PacketRow({ packet, hasAnomaly, isExpanded, onClick }: PacketRowProps) {
  return (
    <>
      <tr
        className={`packet-row ${hasAnomaly ? 'has-anomaly' : ''} ${isExpanded ? 'expanded' : ''}`}
        onClick={onClick}
      >
        <td>{formatTimestamp(packet.timestamp)}</td>
        <td>
          <span className={`protocol-badge ${packet.protocol.toLowerCase()}`}>
            {packet.protocol}
          </span>
        </td>
        <td>{endpoint(packet.src_ip, packet.src_port)}</td>
        <td>{endpoint(packet.dst_ip, packet.dst_port)}</td>
        <td className="mac">{packet.src_mac || '—'} → {packet.dst_mac || '—'}</td>
        <td>{packet.length}</td>
        <td>
          {[packet.tcp_flags, ...packet.anomalies].filter(Boolean).join(' · ') || '—'}
        </td>
      </tr>
      {isExpanded && (
        <tr className="detail-row">
          <td colSpan={7}>
            <div className="packet-detail">
              <div className="detail-grid">
                <div className="detail-item">
                  <span className="detail-label">Timestamp</span>
                  <span className="detail-value">{packet.timestamp}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Protocol</span>
                  <span className="detail-value">{packet.protocol}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Source IP</span>
                  <span className="detail-value">{packet.src_ip || '—'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Destination IP</span>
                  <span className="detail-value">{packet.dst_ip || '—'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Source Port</span>
                  <span className="detail-value">{packet.src_port ?? '—'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Destination Port</span>
                  <span className="detail-value">{packet.dst_port ?? '—'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Source MAC</span>
                  <span className="detail-value">{packet.src_mac || '—'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Destination MAC</span>
                  <span className="detail-value">{packet.dst_mac || '—'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Length</span>
                  <span className="detail-value">{packet.length} bytes</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">TCP Flags</span>
                  <span className="detail-value">{packet.tcp_flags || '—'}</span>
                </div>
                {packet.anomalies.length > 0 && (
                  <div className="detail-item detail-anomalies">
                    <span className="detail-label">Anomalies</span>
                    <span className="detail-value anomaly-text">
                      {packet.anomalies.join(', ')}
                    </span>
                  </div>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts'
import type { Stats } from '../../types'

interface ProtocolPieChartProps {
  distribution: Stats['protocol_distribution']
}

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#3b82f6',
  UDP: '#22c55e',
  ICMP: '#eab308',
  ARP: '#a855f7',
  OTHER: '#6b7280',
}

function getColor(protocol: string): string {
  return PROTOCOL_COLORS[protocol.toUpperCase()] || PROTOCOL_COLORS.OTHER
}

export function ProtocolPieChart({ distribution }: ProtocolPieChartProps) {
  const totalPackets = distribution.reduce((sum, d) => sum + d.count, 0)

  return (
    <div className="chart-card">
      <h3>Protocol Distribution</h3>
      {distribution.length === 0 ? (
        <p className="chart-empty">Waiting for traffic</p>
      ) : (
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie
              data={distribution}
              dataKey="count"
              nameKey="protocol"
              cx="50%"
              cy="50%"
              innerRadius="55%"
              outerRadius="80%"
              paddingAngle={2}
              stroke="none"
            >
              {distribution.map((entry) => (
                <Cell key={entry.protocol} fill={getColor(entry.protocol)} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: '#1e293b',
                border: '1px solid #334155',
                borderRadius: '6px',
                color: '#f1f5f9',
                fontSize: '0.8rem',
              }}
              formatter={(value: any, name: any) => [`${value} packets`, String(name)]}
            />
            <Legend
              verticalAlign="bottom"
              iconType="circle"
              iconSize={8}
              formatter={(value: string) => (
                <span style={{ color: '#94a3b8', fontSize: '0.78rem' }}>{value}</span>
              )}
            />
            {/* Center label */}
            <text
              x="50%"
              y="48%"
              textAnchor="middle"
              dominantBaseline="central"
              fill="#f1f5f9"
              fontSize="1.3rem"
              fontWeight="bold"
            >
              {totalPackets}
            </text>
            <text
              x="50%"
              y="58%"
              textAnchor="middle"
              dominantBaseline="central"
              fill="#64748b"
              fontSize="0.7rem"
            >
              packets
            </text>
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}

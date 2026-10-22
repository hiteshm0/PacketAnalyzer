import { useEffect, useRef, useState } from 'react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import type { Stats } from '../../types'
import { formatBytes } from '../../utils/format'

interface TrafficTimelineProps {
  stats: Stats
}

interface TimePoint {
  time: string
  timestamp: number
  pps: number
  bps: number
}

const MAX_POINTS = 60

export function TrafficTimeline({ stats }: TrafficTimelineProps) {
  const [history, setHistory] = useState<TimePoint[]>([])
  const lastStatsRef = useRef<{ pps: number; bps: number } | null>(null)

  useEffect(() => {
    // Only add a new point if stats actually changed (avoid duplicates)
    const current = { pps: stats.packets_per_second, bps: stats.bytes_per_second }
    const last = lastStatsRef.current

    if (last && last.pps === current.pps && last.bps === current.bps) {
      // Still add a point even if values are same, to keep timeline flowing
    }

    lastStatsRef.current = current

    const now = new Date()
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })

    setHistory(prev => {
      const next = [
        ...prev,
        {
          time: timeStr,
          timestamp: now.getTime(),
          pps: stats.packets_per_second,
          bps: stats.bytes_per_second,
        },
      ]
      return next.slice(-MAX_POINTS)
    })
  }, [stats.packets_per_second, stats.bytes_per_second])

  return (
    <div className="chart-card">
      <h3>Traffic Timeline (60s)</h3>
      {history.length < 2 ? (
        <p className="chart-empty">Collecting data…</p>
      ) : (
        <ResponsiveContainer width="100%" height={260}>
          <AreaChart data={history} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
            <defs>
              <linearGradient id="gradPps" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gradBps" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis
              dataKey="time"
              tick={{ fill: '#64748b', fontSize: 11 }}
              stroke="#334155"
              interval="preserveStartEnd"
            />
            <YAxis
              yAxisId="pps"
              tick={{ fill: '#64748b', fontSize: 11 }}
              stroke="#334155"
              width={45}
            />
            <YAxis
              yAxisId="bps"
              orientation="right"
              tick={{ fill: '#64748b', fontSize: 11 }}
              stroke="#334155"
              width={55}
              tickFormatter={(v: number) => formatBytes(v)}
            />
            <Tooltip
              contentStyle={{
                background: '#1e293b',
                border: '1px solid #334155',
                borderRadius: '6px',
                color: '#f1f5f9',
                fontSize: '0.8rem',
              }}
              formatter={(value: any, name: any) => {
                if (name === 'Bytes/sec') return [formatBytes(Number(value) || 0), String(name)]
                return [value, String(name)]
              }}
            />
            <Legend
              verticalAlign="top"
              iconType="line"
              iconSize={12}
              formatter={(value: string) => (
                <span style={{ color: '#94a3b8', fontSize: '0.78rem' }}>{value}</span>
              )}
            />
            <Area
              yAxisId="pps"
              type="monotone"
              dataKey="pps"
              name="Packets/sec"
              stroke="#3b82f6"
              strokeWidth={2}
              fill="url(#gradPps)"
              dot={false}
              activeDot={{ r: 3, fill: '#3b82f6' }}
            />
            <Area
              yAxisId="bps"
              type="monotone"
              dataKey="bps"
              name="Bytes/sec"
              stroke="#22c55e"
              strokeWidth={2}
              fill="url(#gradBps)"
              dot={false}
              activeDot={{ r: 3, fill: '#22c55e' }}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}

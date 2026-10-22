import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import type { Stats } from '../../types'

interface TopTalkersBarProps {
  topTalkers: Stats['top_talkers']
}

export function TopTalkersBar({ topTalkers }: TopTalkersBarProps) {
  const data = topTalkers.slice(0, 5)

  return (
    <div className="chart-card">
      <h3>Top Talkers</h3>
      {data.length === 0 ? (
        <p className="chart-empty">Waiting for traffic</p>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 5, right: 30, left: 10, bottom: 5 }}
          >
            <defs>
              <linearGradient id="barGrad" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.8} />
                <stop offset="100%" stopColor="#60a5fa" stopOpacity={1} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
            <XAxis
              type="number"
              tick={{ fill: '#64748b', fontSize: 11 }}
              stroke="#334155"
            />
            <YAxis
              type="category"
              dataKey="ip"
              tick={{ fill: '#94a3b8', fontSize: 12 }}
              stroke="#334155"
              width={120}
            />
            <Tooltip
              contentStyle={{
                background: '#1e293b',
                border: '1px solid #334155',
                borderRadius: '6px',
                color: '#f1f5f9',
                fontSize: '0.8rem',
              }}
              formatter={(value: any) => [`${value} packets`, 'Count']}
            />
            <Bar dataKey="packets" radius={[0, 4, 4, 0]} barSize={20}>
              {data.map((_, index) => (
                <Cell key={index} fill="url(#barGrad)" />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}

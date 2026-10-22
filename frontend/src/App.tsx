import { useState, useEffect, useCallback } from 'react'
import type { Filters } from './types'
import { useWebSocket } from './hooks/useWebSocket'
import { useStats } from './hooks/useStats'
import { useCapture } from './hooks/useCapture'
import { Header } from './components/Header'
import { CaptureControls } from './components/CaptureControls'
import { MetricCards } from './components/MetricCards'
import { FilterBar } from './components/FilterBar'
import { PacketTable } from './components/PacketTable'
import { AnomalyBanner } from './components/AnomalyBanner'
import { ProtocolPieChart } from './components/charts/ProtocolPieChart'
import { TrafficTimeline } from './components/charts/TrafficTimeline'
import { TopTalkersBar } from './components/charts/TopTalkersBar'

export default function App() {
  const { stats, error: statsError, setError: setStatsError, refreshStats } = useStats()
  const { packets, setPackets, connectionStatus, sendFilter } = useWebSocket()
  const {
    interfaces,
    selectedInterface,
    setSelectedInterface,
    startCapture,
    stopCapture,
    error: captureError,
  } = useCapture(refreshStats)

  const [filters, setFilters] = useState<Filters>({ protocol: '', ip: '', port: '' })

  // Combine errors
  const error = statsError || captureError

  // Send filter to WebSocket and fetch filtered packets
  useEffect(() => {
    sendFilter(filters)

    const params = new URLSearchParams()
    if (filters.protocol) params.set('protocol', filters.protocol)
    if (filters.ip) params.set('ip', filters.ip)
    if (filters.port) params.set('port', filters.port)

    fetch(`/api/packets?${params}`)
      .then(r => r.json())
      .then(data => setPackets(data.packets))
      .catch(() => undefined)
  }, [filters, sendFilter, setPackets])

  const changeFilter = useCallback((key: keyof Filters, value: string) => {
    setFilters(current => ({ ...current, [key]: value }))
  }, [])

  const clearFilters = useCallback(() => {
    setFilters({ protocol: '', ip: '', port: '' })
  }, [])

  return (
    <main>
      <Header
        captureRunning={stats.capture_running}
        captureInterface={stats.interface}
        connectionStatus={connectionStatus}
      />

      {error && (
        <p className="error" onClick={() => setStatsError('')}>
          {error}
        </p>
      )}

      <AnomalyBanner packets={packets} />

      <CaptureControls
        interfaces={interfaces}
        selectedInterface={selectedInterface}
        onSelectInterface={setSelectedInterface}
        onStart={startCapture}
        onStop={stopCapture}
        captureRunning={stats.capture_running}
      />

      <MetricCards stats={stats} />

      <div className="dashboard-grid">
        <ProtocolPieChart distribution={stats.protocol_distribution} />
        <TrafficTimeline stats={stats} />
        <TopTalkersBar topTalkers={stats.top_talkers} />
      </div>

      <FilterBar
        filters={filters}
        onChangeFilter={changeFilter}
        onClearFilters={clearFilters}
      />

      <PacketTable packets={packets} />
    </main>
  )
}

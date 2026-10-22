import { useEffect, useState, useCallback } from 'react'
import type { Stats } from '../types'

const emptyStats: Stats = {
  captured_packets: 0,
  buffer_capacity: 5000,
  packets_per_second: 0,
  bytes_per_second: 0,
  capture_running: false,
  protocol_distribution: [],
  top_talkers: [],
  top_destination_ports: [],
}

interface UseStatsReturn {
  stats: Stats
  error: string
  setError: React.Dispatch<React.SetStateAction<string>>
  refreshStats: () => Promise<void>
}

export function useStats(): UseStatsReturn {
  const [stats, setStats] = useState<Stats>(emptyStats)
  const [error, setError] = useState('')

  const refreshStats = useCallback(async () => {
    try {
      const response = await fetch('/api/stats')
      const data = await response.json()
      setStats(data)
    } catch {
      setError('Backend unavailable. Start the FastAPI server first.')
    }
  }, [])

  useEffect(() => {
    refreshStats()
    const timer = window.setInterval(refreshStats, 1000)
    return () => window.clearInterval(timer)
  }, [refreshStats])

  return { stats, error, setError, refreshStats }
}

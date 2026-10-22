import { useState, useMemo } from 'react'
import { AlertTriangle, X } from 'lucide-react'
import type { Packet } from '../types'

interface AnomalyBannerProps {
  packets: Packet[]
}

export function AnomalyBanner({ packets }: AnomalyBannerProps) {
  const [dismissed, setDismissed] = useState(false)

  const anomalyInfo = useMemo(() => {
    const anomalyPackets = packets.filter(p => p.anomalies.length > 0)
    const allAnomalies = anomalyPackets.flatMap(p => p.anomalies)
    const uniqueTypes = [...new Set(allAnomalies)]
    return { count: anomalyPackets.length, types: uniqueTypes }
  }, [packets])

  if (dismissed || anomalyInfo.count === 0) return null

  return (
    <div className="anomaly-banner">
      <AlertTriangle size={18} className="anomaly-icon pulse" />
      <div className="anomaly-content">
        <strong>{anomalyInfo.count} anomal{anomalyInfo.count === 1 ? 'y' : 'ies'} detected</strong>
        <span className="anomaly-types">{anomalyInfo.types.join(', ')}</span>
      </div>
      <button className="anomaly-dismiss" onClick={() => setDismissed(true)}>
        <X size={14} />
      </button>
    </div>
  )
}

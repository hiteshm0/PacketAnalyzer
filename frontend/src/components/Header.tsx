import { Activity, Wifi, WifiOff } from 'lucide-react'

interface HeaderProps {
  captureRunning: boolean
  captureInterface?: string
  connectionStatus: 'connecting' | 'open' | 'closed'
}

export function Header({ captureRunning, captureInterface, connectionStatus }: HeaderProps) {
  return (
    <header>
      <div className="header-left">
        <div className="header-title">
          <Activity size={28} className="header-icon" />
          <div>
            <h1>Network Traffic Analyzer</h1>
            <p className="header-subtitle">Live packet capture and parsing</p>
          </div>
        </div>
      </div>
      <div className="header-right">
        <div className="connection-indicator">
          {connectionStatus === 'open' ? (
            <Wifi size={14} className="conn-icon connected" />
          ) : (
            <WifiOff size={14} className="conn-icon disconnected" />
          )}
          <span className="conn-text">
            {connectionStatus === 'open' ? 'Live' : connectionStatus === 'connecting' ? 'Connecting…' : 'Disconnected'}
          </span>
        </div>
        <div className={captureRunning ? 'status running' : 'status'}>
          <span className={`status-dot ${captureRunning ? 'pulse' : ''}`} />
          {captureRunning ? `Capturing: ${captureInterface}` : 'Stopped'}
        </div>
      </div>
    </header>
  )
}

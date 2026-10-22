import { Play, Square } from 'lucide-react'

interface CaptureControlsProps {
  interfaces: string[]
  selectedInterface: string
  onSelectInterface: (iface: string) => void
  onStart: () => void
  onStop: () => void
  captureRunning: boolean
}

export function CaptureControls({
  interfaces,
  selectedInterface,
  onSelectInterface,
  onStart,
  onStop,
  captureRunning,
}: CaptureControlsProps) {
  return (
    <section className="controls">
      <select value={selectedInterface} onChange={e => onSelectInterface(e.target.value)}>
        {interfaces.map(name => (
          <option key={name}>{name}</option>
        ))}
      </select>
      <button onClick={onStart} disabled={captureRunning}>
        <Play size={14} />
        Start capture
      </button>
      <button className="secondary" onClick={onStop} disabled={!captureRunning}>
        <Square size={14} />
        Stop
      </button>
    </section>
  )
}

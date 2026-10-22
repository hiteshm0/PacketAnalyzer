import { useEffect, useState, useCallback } from 'react'

interface UseCaptureReturn {
  interfaces: string[]
  selectedInterface: string
  setSelectedInterface: React.Dispatch<React.SetStateAction<string>>
  startCapture: () => Promise<void>
  stopCapture: () => Promise<void>
  error: string
  setError: React.Dispatch<React.SetStateAction<string>>
}

export function useCapture(onAfterAction?: () => Promise<void>): UseCaptureReturn {
  const [interfaces, setInterfaces] = useState<string[]>([])
  const [selectedInterface, setSelectedInterface] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    fetch('/api/interfaces')
      .then(r => r.json())
      .then(data => {
        setInterfaces(data.interfaces)
        setSelectedInterface(data.default || '')
      })
      .catch(() => setError('Could not load interfaces.'))
  }, [])

  const startCapture = useCallback(async () => {
    setError('')
    try {
      const response = await fetch('/api/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedInterface || null }),
      })
      if (!response.ok) {
        const data = await response.json()
        setError(data.detail || 'Capture control failed.')
      }
    } catch {
      setError('Failed to start capture.')
    }
    if (onAfterAction) await onAfterAction()
  }, [selectedInterface, onAfterAction])

  const stopCapture = useCallback(async () => {
    setError('')
    try {
      const response = await fetch('/api/capture/stop', { method: 'POST' })
      if (!response.ok) {
        const data = await response.json()
        setError(data.detail || 'Capture control failed.')
      }
    } catch {
      setError('Failed to stop capture.')
    }
    if (onAfterAction) await onAfterAction()
  }, [onAfterAction])

  return { interfaces, selectedInterface, setSelectedInterface, startCapture, stopCapture, error, setError }
}

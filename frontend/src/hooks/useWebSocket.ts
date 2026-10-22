import { useEffect, useRef, useState, useCallback } from 'react'
import type { Packet, Filters } from '../types'

const MAX_ROWS = 250
const MAX_BACKOFF = 30000

type ConnectionStatus = 'connecting' | 'open' | 'closed'

interface UseWebSocketReturn {
  packets: Packet[]
  setPackets: React.Dispatch<React.SetStateAction<Packet[]>>
  connectionStatus: ConnectionStatus
  sendFilter: (filters: Filters) => void
}

export function useWebSocket(): UseWebSocketReturn {
  const [packets, setPackets] = useState<Packet[]>([])
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('connecting')
  const socketRef = useRef<WebSocket | null>(null)
  const reconnectAttempt = useRef(0)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const mountedRef = useRef(true)

  const connect = useCallback(() => {
    if (!mountedRef.current) return

    setConnectionStatus('connecting')
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${wsProtocol}//${window.location.host}/ws/packets`)
    socketRef.current = ws

    ws.onopen = () => {
      if (!mountedRef.current) { ws.close(); return }
      reconnectAttempt.current = 0
      setConnectionStatus('open')
    }

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data)
      if (message.type === 'packet') {
        setPackets(rows => [message.packet, ...rows].slice(0, MAX_ROWS))
      }
    }

    ws.onerror = () => {
      // onclose will fire after this
    }

    ws.onclose = () => {
      if (!mountedRef.current) return
      setConnectionStatus('closed')
      socketRef.current = null

      // Exponential backoff reconnect
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempt.current), MAX_BACKOFF)
      reconnectAttempt.current += 1
      reconnectTimer.current = setTimeout(connect, delay)
    }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    connect()

    return () => {
      mountedRef.current = false
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      if (socketRef.current) {
        socketRef.current.onclose = null // prevent reconnect on intentional close
        socketRef.current.close()
      }
    }
  }, [connect])

  const sendFilter = useCallback((filters: Filters) => {
    if (socketRef.current?.readyState === WebSocket.OPEN) {
      try {
        socketRef.current.send(JSON.stringify({
          type: 'filter',
          filter: {
            protocol: filters.protocol || null,
            ip: filters.ip || null,
            port: filters.port ? Number(filters.port) : null,
          },
        }))
      } catch {
        /* ignored */
      }
    }
  }, [])

  return { packets, setPackets, connectionStatus, sendFilter }
}

export type Packet = {
  timestamp: string
  src_mac?: string
  dst_mac?: string
  src_ip?: string
  dst_ip?: string
  src_port?: number
  dst_port?: number
  protocol: string
  length: number
  tcp_flags?: string
  anomalies: string[]
}

export type Stats = {
  captured_packets: number
  buffer_capacity: number
  packets_per_second: number
  bytes_per_second: number
  capture_running: boolean
  interface?: string
  capture_error?: string
  protocol_distribution: { protocol: string; count: number; percent: number }[]
  top_talkers: { ip: string; packets: number }[]
  top_destination_ports: { port: number; packets: number }[]
}

export type Filters = {
  protocol: string
  ip: string
  port: string
}

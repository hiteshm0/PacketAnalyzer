export function formatBytes(bytes: number): string {
  if (bytes > 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

export function formatTimestamp(iso: string): string {
  return new Date(iso).toLocaleTimeString()
}

export function endpoint(ip?: string, port?: number): string {
  return ip ? `${ip}${port !== undefined ? `:${port}` : ''}` : '—'
}

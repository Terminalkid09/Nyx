type EventHandler = (data: any) => void

class NyxWebSocket {
  private ws: WebSocket | null = null
  private handlers: Map<string, EventHandler[]> = new Map()
  private reconnectDelay = 1000
  private url: string

  constructor(url: string) {
    this.url = url
  }

  connect() {
    this.ws = new WebSocket(this.url)

    this.ws.onopen = () => {
      console.log('[Nyx WS] Connected')
      this.reconnectDelay = 1000
    }

    this.ws.onmessage = (e: MessageEvent) => {
      try {
        const event = JSON.parse(e.data)
        const handlers = this.handlers.get(event.type) || []
        handlers.forEach((h) => h(event))
      } catch {}
    }

    this.ws.onclose = () => {
      console.warn(`[Nyx WS] Disconnected — reconnecting in ${this.reconnectDelay}ms`)
      setTimeout(() => this.connect(), this.reconnectDelay)
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30_000)
    }

    this.ws.onerror = () => {
      this.ws?.close()
    }
  }

  on(type: string, handler: EventHandler): () => void {
    if (!this.handlers.has(type)) this.handlers.set(type, [])
    this.handlers.get(type)!.push(handler)
    return () => {
      const arr = this.handlers.get(type) || []
      this.handlers.set(type, arr.filter((h) => h !== handler))
    }
  }

  ping() {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send('ping')
    }
  }
}

const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
const WS_URL = import.meta.env.VITE_WS_URL || `${wsProtocol}//${window.location.host}`
export const nyxWs = new NyxWebSocket(`${WS_URL}/ws/traffic`)

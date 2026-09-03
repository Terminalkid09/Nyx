/**
 * Nyx WebSocket client — singleton that manages the /ws/traffic connection.
 *
 * Key improvements vs the previous version:
 * - `isConnected` flag so components can react to connection state.
 * - Dedicated `connected` / `disconnected` event types fired on the handler
 *   map so the UI banner can react without polling.
 * - Max-retry counter: after 10 consecutive failures we stop auto-reconnecting
 *   and fire a `ws.error` event so the user sees a permanent banner.
 * - Guards against double-connect: `connect()` is a no-op if already OPEN or
 *   CONNECTING.
 * - Prevents duplicate `onclose` listeners accumulating on reconnect.
 */

type EventHandler = (data: any) => void

const MAX_RETRIES = 10

class NyxWebSocket {
  private ws: WebSocket | null = null
  private handlers: Map<string, EventHandler[]> = new Map()
  private reconnectDelay = 1000
  private retryCount = 0
  private _isConnected = false
  private url: string

  constructor(url: string) {
    this.url = url
  }

  get isConnected(): boolean {
    return this._isConnected
  }

  connect() {
    // Prevent double-connect
    if (
      this.ws &&
      (this.ws.readyState === WebSocket.OPEN ||
        this.ws.readyState === WebSocket.CONNECTING)
    ) {
      return
    }

    this.ws = new WebSocket(this.url)

    this.ws.onopen = () => {
      console.log('[Nyx WS] Connected')
      this._isConnected = true
      this.reconnectDelay = 1000
      this.retryCount = 0
      this._emit('ws.connected', { connected: true })
    }

    this.ws.onmessage = (e: MessageEvent) => {
      try {
        const event = JSON.parse(e.data)
        const handlers = this.handlers.get(event.type) || []
        handlers.forEach((h) => h(event))
      } catch {
        // ignore malformed frames
      }
    }

    this.ws.onclose = () => {
      this._isConnected = false
      this._emit('ws.disconnected', { connected: false })

      if (this.retryCount >= MAX_RETRIES) {
        console.error(
          `[Nyx WS] Max retries (${MAX_RETRIES}) reached — giving up.`
        )
        this._emit('ws.error', {
          message: `WebSocket reconnection failed after ${MAX_RETRIES} attempts. Refresh the page or restart Nyx.`,
        })
        return
      }

      this.retryCount++
      console.warn(
        `[Nyx WS] Disconnected — reconnecting in ${this.reconnectDelay}ms (attempt ${this.retryCount}/${MAX_RETRIES})`
      )
      setTimeout(() => this.connect(), this.reconnectDelay)
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30_000)
    }

    this.ws.onerror = () => {
      // onerror is always followed by onclose — just close cleanly
      this.ws?.close()
    }
  }

  /** Force a reconnect (e.g. user clicks "Reconnect" button) */
  reconnect() {
    this.retryCount = 0
    this.reconnectDelay = 1000
    if (this.ws) {
      // Suppress the auto-reconnect triggered by this close
      this.ws.onclose = null
      this.ws.close()
    }
    this._isConnected = false
    this.connect()
  }

  on(type: string, handler: EventHandler): () => void {
    if (!this.handlers.has(type)) this.handlers.set(type, [])
    this.handlers.get(type)!.push(handler)
    return () => {
      const arr = this.handlers.get(type) || []
      this.handlers.set(
        type,
        arr.filter((h) => h !== handler)
      )
    }
  }

  ping() {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send('ping')
    }
  }

  private _emit(type: string, data: any) {
    const handlers = this.handlers.get(type) || []
    handlers.forEach((h) => h(data))
  }
}

const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
const WS_URL =
  import.meta.env.VITE_WS_URL || `${wsProtocol}//${window.location.host}`
export const nyxWs = new NyxWebSocket(`${WS_URL}/ws/traffic`)

import { useEffect, useState } from 'react'
import { nyxWs } from '../api/websocket'
import { apiClient } from '../api/client'
import { useProxyStore } from '../store/useProxyStore'
import { useFindingsStore } from '../store/useFindingsStore'
import { useSessionStore } from '../store/useSessionStore'

/**
 * Global WebSocket hook — mount once in <App />.
 *
 * Events are filtered to the active session so that switching sessions
 * only shows live traffic for that session.
 */
export function useWebSocket() {
  const addRequest = useProxyStore((s) => s.addRequest)
  const updateResponse = useProxyStore((s) => s.updateResponse)
  const clearRequests = useProxyStore((s) => s.clearRequests)
  const addFinding = useFindingsStore((s) => s.addFinding)
  const activeSessionId = useSessionStore((s) => s.activeSessionId)

  const [wsState, setWsState] = useState<'connected' | 'disconnected' | 'error'>(
    nyxWs.isConnected ? 'connected' : 'disconnected'
  )

  useEffect(() => {
    // The active session is persisted in localStorage, but the backend's
    // proxy session stamp only changes when the user clicks a session
    // (activateSession). After an app restart the UI can therefore sit on
    // "Test_session" while the proxy still stamps "Default Session" — new
    // MITM captures are then filtered out and never appear in the Proxy tab.
    // Sync the proxy to the persisted active session on startup.
    apiClient
      .get('/api/proxy/session')
      .then(({ data }) => {
        if (activeSessionId && data.session_id !== activeSessionId) {
          apiClient
            .patch('/api/proxy/session', { session_id: activeSessionId })
            .catch(() => {})
        }
      })
      .catch(() => {})

    let mounted = true
    // The packaged backend exe takes a few seconds to boot, so the initial
    // history fetch can race it and fail — leaving the Proxy tab empty at
    // startup. Retry once the WebSocket connects (i.e. the backend is up).
    let historyLoaded = false
    const loadHistory = async () => {
      try {
        const { data } = await apiClient.get('/api/requests', {
          params: { session_id: activeSessionId, per_page: 500 }
        })
        if (mounted) {
          clearRequests()
          // Reverse them since addRequest prepends
          data.items.slice().reverse().forEach((req: any) => addRequest(req))
          historyLoaded = true
        }
      } catch (err) {
        console.error('Failed to load proxy history', err)
      }
    }
    // Load persisted proxy history for the active session so every module
    // (ProxyLog, Repeater, Fuzzer, Comparer, ...) sees old requests right
    // after startup, not just live traffic captured since Nyx was opened.
    if (activeSessionId) loadHistory()

    // Connect once �?" the singleton guards against double-connects
    nyxWs.connect()

    const unsubs = [
      nyxWs.on('request.captured', (e) => {
        // Only show traffic for the active session
        if (e.session_id && e.session_id !== activeSessionId) return
        addRequest({
          ...e,
          id: e.request_id,
          http_version: e.http_version || 'HTTP/1.1',
          timestamp: e.timestamp || new Date().toISOString(),
          is_flagged: false,
          tags: [],
          api_type: null,
          tls_version: null,
          notes: null,
          response_status: null,
          response_reason: null,
          response_headers: null,
          response_body: null,
          response_content_type: null,
          response_size_bytes: null,
          response_time_ms: null,
        })
      }),
      nyxWs.on('response.received', (e) => {
        if (e.session_id && e.session_id !== activeSessionId) return
        updateResponse(e.request_id, {
          response_status: e.status,
          response_reason: e.reason || '',
          response_headers: e.headers,
          response_body: e.body,
          response_content_type: e.content_type,
          response_size_bytes: e.size_bytes,
          response_time_ms: e.response_time_ms,
        })
      }),
      nyxWs.on('finding.created', (e) => {
        if (e.session_id && e.session_id !== activeSessionId) return
        addFinding(e)
      }),
      nyxWs.on('ws.connected', () => {
        setWsState('connected')
        // The backend is now up — retry the history fetch if the initial
        // attempt failed (backend boot race).
        if (!historyLoaded && mounted && activeSessionId) loadHistory()
      }),
      nyxWs.on('ws.disconnected', () => setWsState('disconnected')),
      nyxWs.on('ws.error', () => setWsState('error')),
    ]

    // Ping every 30 s to keep the connection alive
    const pingInterval = setInterval(() => nyxWs.ping(), 30_000)

    return () => {
      mounted = false
      unsubs.forEach((u) => u())
      clearInterval(pingInterval)
    }
  // Re-subscribe when active session changes so filter updates
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSessionId])

  return { wsState }
}

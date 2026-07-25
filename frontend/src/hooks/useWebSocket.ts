import { useEffect } from 'react'
import { nyxWs } from '../api/websocket'
import { useProxyStore } from '../store/useProxyStore'
import { useFindingsStore } from '../store/useFindingsStore'

export function useWebSocket() {
  const addRequest = useProxyStore((s) => s.addRequest)
  const updateResponse = useProxyStore((s) => s.updateResponse)
  const addFinding = useFindingsStore((s) => s.addFinding)

  useEffect(() => {
    nyxWs.connect()

    const unsubs = [
      nyxWs.on('request.captured', (e) => addRequest(e)),
      nyxWs.on('response.received', (e) =>
        updateResponse(e.request_id, {
          response_status: e.status,
          response_headers: e.headers,
          response_body: e.body,
          response_size_bytes: e.size_bytes,
          response_time_ms: e.response_time_ms,
        }),
      ),
      nyxWs.on('finding.created', (e) => addFinding(e)),
    ]

    const pingInterval = setInterval(() => nyxWs.ping(), 30_000)

    return () => {
      unsubs.forEach((u) => u())
      clearInterval(pingInterval)
    }
  }, [])
}

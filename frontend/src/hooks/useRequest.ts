import { useState } from 'react'
import { apiClient } from '../api/client'
import { useSessionStore } from '../store/useSessionStore'

export function useRequest() {
  const activeSessionId = useSessionStore((s) => s.activeSessionId)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const send = async (method: string, url: string, headers: Record<string, string>, body?: string) => {
    setLoading(true)
    setError(null)
    try {
      const { data } = await apiClient.post('/api/repeater/send', {
        method,
        url,
        headers,
        body: body || null,
        session_id: activeSessionId,
      })
      return data
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
      return null
    } finally {
      setLoading(false)
    }
  }

  return { send, loading, error }
}

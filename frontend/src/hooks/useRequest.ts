import { useState } from 'react'
import { apiClient } from '../api/client'

export function useRequest() {
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

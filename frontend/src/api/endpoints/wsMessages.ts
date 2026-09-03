import { apiClient } from '../client'

export interface WSMessage {
  id: string; session_id: string; request_id: string
  direction: string; timestamp: string; payload: string | null
  is_binary: boolean; payload_size: number
}

export async function listWSMessages(sessionId?: string, requestId?: string): Promise<WSMessage[]> {
  const params: any = {}
  if (sessionId) params.session_id = sessionId
  if (requestId) params.request_id = requestId
  const r = await apiClient.get('/api/ws/messages', { params })
  return r.data
}

export async function deleteWSMessage(id: string): Promise<void> {
  await apiClient.delete(`/api/ws/messages/${id}`)
}

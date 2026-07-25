import { apiClient } from '../client'
import { WebSocketMsg } from '../../types'

export async function fetchWebSocketMessages(sessionId?: string, requestId?: string): Promise<WebSocketMsg[]> {
  const { data } = await apiClient.get<WebSocketMsg[]>('/api/ws/messages', { params: { session_id: sessionId, request_id: requestId } })
  return data
}

export async function deleteWebSocketMessage(id: string): Promise<void> {
  await apiClient.delete(`/api/ws/messages/${id}`)
}

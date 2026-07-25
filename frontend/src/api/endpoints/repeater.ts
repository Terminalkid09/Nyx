import { apiClient } from '../client'

export interface RepeaterTab {
  id: string
  name: string
  created_at: string
  history_count: number
}

export interface RepeaterResponse {
  status: number
  headers: Record<string, string>
  body: string | null
  time_ms: number
}

export interface HistoryEntry {
  method: string
  url: string
  headers: Record<string, string>
  body: string | null
  response_status: number | null
  response_headers: Record<string, string> | null
  response_body: string | null
  time_ms: number | null
  timestamp: string
}

export async function sendRequest(
  method: string,
  url: string,
  headers?: Record<string, string>,
  body?: string
): Promise<RepeaterResponse> {
  const { data } = await apiClient.post<RepeaterResponse>('/api/repeater/send', {
    method,
    url,
    headers: headers || {},
    body: body || null,
  })
  return data
}

export async function fetchTabs(): Promise<RepeaterTab[]> {
  const { data } = await apiClient.get<RepeaterTab[]>('/api/repeater/tabs')
  return data
}

export async function createTab(name?: string, requestData?: { method: string; url: string; headers: Record<string, string>; body?: string }): Promise<RepeaterTab> {
  const { data } = await apiClient.post<RepeaterTab>('/api/repeater/tabs', {
    name: name || 'Untitled',
    request_data: requestData || null,
  })
  return data
}

export async function closeTab(id: string): Promise<void> {
  await apiClient.delete(`/api/repeater/tabs/${id}`)
}

export async function fetchTabHistory(id: string): Promise<HistoryEntry[]> {
  const { data } = await apiClient.get<HistoryEntry[]>(`/api/repeater/tabs/${id}/history`)
  return data
}

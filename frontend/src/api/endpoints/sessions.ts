import { apiClient } from '../client'
import { NyxSession } from '../../types'

export async function fetchSessions(): Promise<NyxSession[]> {
  const { data } = await apiClient.get<NyxSession[]>('/api/sessions')
  return data
}

export async function createSession(name: string): Promise<NyxSession> {
  const { data } = await apiClient.post<NyxSession>('/api/sessions', { name })
  return data
}

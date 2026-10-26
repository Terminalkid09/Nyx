import { apiClient } from '../client'

export interface VerifyRequest {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: string | null
  param?: string | null
  payload?: string | null
  session_id?: string | null
}

export interface VerifyVerdict {
  verdict: 'confirmed' | 'probable' | 'unverified'
  signals: string[]
  status_delta: number
  length_delta: number
  time_delta_ms: number
  similarity: number
}

export async function verifyExploit(input: VerifyRequest): Promise<VerifyVerdict> {
  const { data } = await apiClient.post<VerifyVerdict>('/api/auto-exploit/verify', input)
  return data
}

import { apiClient } from '../client'

export interface AbIdentity {
  name: string
  headers: Record<string, string>
}

export interface AbTestRequest {
  url: string
  method: string
  headers: Record<string, string>
  body?: string | null
  identity_a: AbIdentity
  identity_b: AbIdentity
  anonymous: boolean
  session_id?: string | null
}

export interface AbSample {
  label: string
  status: number | null
  length: number
  content_type: string | null
  location: string | null
  challenge: boolean
  time_ms: number
  error: string | null
  body_preview: string
}

export interface AbTestResult {
  verdict: 'suspected_idor' | 'isolated' | 'unauthenticated_access' | string
  severity: string | null
  confidence: number
  similarity: number
  signals: string[]
  samples: AbSample[]
}

export async function runAbTest(body: AbTestRequest): Promise<AbTestResult> {
  const { data } = await apiClient.post<AbTestResult>('/api/ab-test/run', body, {
    // Two identities plus the anonymous leg, each a full round-trip: the
    // default 30s client timeout is tight against a slow target.
    timeout: 90000,
  })
  return data
}

import { apiClient } from '../client'

export interface FuzzPositionConfig {
  name: string
  wordlist_path: string
  processors?: string[]
}

export interface FuzzGrepMatchConfig {
  name: string
  pattern: string
  is_regex?: boolean
}

export interface FuzzExtractorConfig {
  name: string
  pattern: string
  is_regex?: boolean
  group?: number
}

export interface FuzzCreatePayload {
  session_id: string
  base_request_id: string
  request_template: string
  attack_type: string
  positions: FuzzPositionConfig[]
  grep_matches?: FuzzGrepMatchConfig[]
  extractors?: FuzzExtractorConfig[]
  rate_limit_rps?: number
}

export interface FuzzJobResponse {
  id: string
  session_id: string
  base_request_id: string
  status: string
  total_requests: number
  completed_requests: number
  attack_type: string
  wordlist_name: string
  rate_limit_rps: number
  positions: any[]
  grep_matches: any[]
  extractors: any[]
  request_template: string
  results: any[]
}

export async function fetchFuzzJobs(): Promise<FuzzJobResponse[]> {
  const { data } = await apiClient.get<FuzzJobResponse[]>('/api/fuzzer/jobs')
  return data
}

export async function createFuzzJob(job: FuzzCreatePayload): Promise<FuzzJobResponse> {
  const { data } = await apiClient.post<FuzzJobResponse>('/api/fuzzer/jobs', job)
  return data
}

export async function getFuzzJob(id: string): Promise<FuzzJobResponse> {
  const { data } = await apiClient.get<FuzzJobResponse>(`/api/fuzzer/jobs/${id}`)
  return data
}

export async function getFuzzJobResults(id: string, statusFilter?: number): Promise<any[]> {
  const params = statusFilter !== undefined ? { status_filter: statusFilter } : {}
  const { data } = await apiClient.get<any[]>(`/api/fuzzer/jobs/${id}/results`, { params })
  return data
}

export async function cancelFuzzJob(id: string): Promise<void> {
  await apiClient.post(`/api/fuzzer/jobs/${id}/cancel`)
}

export async function fetchWordlists(): Promise<string[]> {
  const { data } = await apiClient.get<string[]>('/api/fuzzer/wordlists')
  return data
}

export async function previewFuzzJob(config: {
  request_template: string
  attack_type: string
  positions: FuzzPositionConfig[]
}): Promise<{ total_requests: number }> {
  const { data } = await apiClient.post<{ total_requests: number }>('/api/fuzzer/preview', config)
  return data
}

export async function fetchAttackTypes(): Promise<string[]> {
  const { data } = await apiClient.get<string[]>('/api/fuzzer/attack-types')
  return data
}

export async function fetchProcessors(): Promise<string[]> {
  const { data } = await apiClient.get<string[]>('/api/fuzzer/processors')
  return data
}

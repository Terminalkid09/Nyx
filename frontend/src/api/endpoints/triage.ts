import { apiClient } from '../client'

export interface TriageGroup {
  key: string; title: string; severity: string; count: number
  endpoint: string; vuln_type: string; evidence_preview: string
  host: string; method: string; url: string
  request_headers: Record<string, string>; request_body: string
  request_id: string; request_session_id: string
  first_seen: string; last_seen: string
}

export interface TriageStats {
  total_findings: number; critical: number; high: number; medium: number; low: number
  unique_vuln_types: string[]; unique_endpoints: string[]
  proxy_requests_today: number; active_pipelines: number
  discovery_jobs_running: number; fuzz_jobs_running: number
}

export interface RecentFinding {
  id: string; title: string; severity: string; method: string
  url: string; status: number | null; created_at: string
}

export async function getGroupedFindings(sessionId: string): Promise<{ groups: TriageGroup[] }> {
  const r = await apiClient.get('/api/triage/findings/grouped', { params: { session_id: sessionId } })
  return r.data
}

export async function retestFinding(id: string): Promise<{ result: string; evidence: string; status_code: number }> {
  const r = await apiClient.get(`/api/triage/findings/${id}/retest`)
  return r.data
}

export async function getTriageStats(sessionId: string): Promise<TriageStats> {
  const r = await apiClient.get('/api/triage/stats', { params: { session_id: sessionId } })
  return r.data
}

export async function getRecentFindings(sessionId: string, hours = 24): Promise<RecentFinding[]> {
  const r = await apiClient.get('/api/triage/findings/recent', { params: { session_id: sessionId, hours } })
  return r.data
}

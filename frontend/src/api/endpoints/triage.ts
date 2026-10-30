import { apiClient } from '../client'

export type TriageStatus =
  | 'open'
  | 'confirmed'
  | 'needs_review'
  | 'fixed'
  | 'false_positive'

export interface TriageGroup {
  key: string; title: string; severity: string; count: number
  endpoint: string; vuln_type: string; evidence_preview: string
  host: string; method: string; url: string
  request_headers: Record<string, string>; request_body: string
  request_id: string; request_session_id: string
  first_seen: string; last_seen: string
  severity_override: string | null; triage_status: TriageStatus
  finding_ids: string[]
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
  triage_status: TriageStatus
}

export interface FindingUpdate {
  triage_status?: TriageStatus
  severity?: string
  clear_severity_override?: boolean
}

export interface FindingUpdateResult {
  id: string
  triage_status: TriageStatus
  severity: string
  severity_override: string | null
}

export interface RetestResult {
  // 'not_retestable': the finding has no stored request to replay (an old
  // finding whose request was purged, or one created without a URL).
  result: 'confirmed' | 'needs_review' | 'error' | 'not_retestable'
  evidence: string
  status_code?: number
  triage_status?: TriageStatus
}

export const TRIAGE_STATUS_LABELS: Record<TriageStatus, string> = {
  open: 'Open',
  confirmed: 'Confirmed',
  needs_review: 'Needs review',
  fixed: 'Fixed',
  false_positive: 'False positive',
}

export async function getGroupedFindings(
  sessionId: string,
  includeTriaged = false,
): Promise<{ groups: TriageGroup[] }> {
  const r = await apiClient.get('/api/triage/findings/grouped', {
    params: { session_id: sessionId, include_triaged: includeTriaged },
  })
  return r.data
}

export async function updateFinding(id: string, body: FindingUpdate): Promise<FindingUpdateResult> {
  const r = await apiClient.patch(`/api/triage/findings/${id}`, body)
  return r.data
}

export async function retestFinding(id: string): Promise<RetestResult> {
  const r = await apiClient.get(`/api/triage/findings/${id}/retest`, { timeout: 60000 })
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

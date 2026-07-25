export interface NyxRequest {
  id: string
  session_id: string
  timestamp: string
  method: string
  url: string
  host: string
  path: string
  http_version: string
  request_headers: Record<string, string>
  request_body: string | null
  response_status: number | null
  response_reason: string | null
  response_headers: Record<string, string> | null
  response_body: string | null
  response_content_type: string | null
  response_size_bytes: number | null
  response_time_ms: number | null
  is_flagged: boolean
  tags: string[]
  api_type: 'rest' | 'graphql' | 'grpc' | null
  tls_version: string | null
  notes: string | null
}

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface NyxFinding {
  id: string
  session_id: string
  request_id: string | null
  created_at: string
  module: string
  severity: Severity
  title: string
  description: string
  evidence: string | null
  remediation: string | null
  cwe: string | null
  cvss_score: number | null
}

export interface NyxSession {
  id: string
  name: string
  created_at: string
  updated_at: string
  scope: string[]
  notes: string | null
  is_active: boolean
}

export interface InterceptorRule {
  id: string
  session_id: string
  enabled: boolean
  name: string
  scope: 'request' | 'response' | 'both'
  intercept_on_match: boolean
  match_type: string | null
  match_pattern: string | null
  is_regex: boolean
  order: number
}

export interface InterceptedItem {
  id: string
  request_id: string
  created_at: string
  direction: string
  status: string
  modified_method: string | null
  modified_url: string | null
  modified_headers: Record<string, string> | null
  modified_body: string | null
  action: string | null
}

export interface SessionHandlingRule {
  id: string
  session_id: string
  name: string
  rule_type: 'cookie_jar' | 'macro' | 'session_check'
  enabled: boolean
  config: Record<string, unknown>
  order: number
}

export interface CookieEntry {
  id: string
  session_id: string
  domain: string
  name: string
  value: string
  path: string
  secure: boolean
  http_only: boolean
  same_site: string | null
  expires: string | null
  created_at: string
}

export interface ComparerItem {
  id: string
  session_id: string
  left_request_id: string | null
  right_request_id: string | null
  left_type: string
  right_type: string
  left_content: string | null
  right_content: string | null
  left_label: string | null
  right_label: string | null
  created_at: string
  notes: string | null
}

export interface DiffResult {
  added: string[]
  removed: string[]
  unchanged: string[]
  sections: { type: string; lines: string[] }[]
}

export interface Plugin {
  id: string
  name: string
  path: string
  enabled: boolean
  hook_type: string
  description: string | null
  version: string
  config: Record<string, unknown>
  created_at: string
}

export interface Project {
  id: string
  name: string
  description: string | null
  session_id: string | null
  created_at: string
  updated_at: string
  project_data: Record<string, unknown>
}

export interface ScanJob {
  id: string
  session_id: string
  scan_type: string
  target_url: string | null
  config: Record<string, unknown>
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  total_tasks: number
  completed_tasks: number
  created_at: string
  started_at: string | null
  completed_at: string | null
}

export interface WebSocketMsg {
  id: string
  session_id: string
  request_id: string
  direction: string
  timestamp: string
  payload: string | null
  is_binary: boolean
  payload_size: number
}

export interface AuthJwtResult {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: string
  issues: { type: string; severity: string; description: string }[]
}

export interface SearchResult {
  type: string
  id: string
  snippet: string
  match_location: string
  url: string | null
}

export interface FuzzJobExtended extends FuzzJob {
  attack_type: string
  positions: { name: string; value: string; wordlist_index: number }[]
  grep_matches: { name: string; pattern: string; is_regex: boolean }[]
  extractors: { name: string; pattern: string; is_regex: boolean; group: number }[]
  request_template: string
}

export interface FuzzJob {
  id: string
  session_id: string
  status: 'pending' | 'running' | 'done' | 'cancelled'
  total_requests: number
  completed_requests: number
  wordlist_name: string
  rate_limit_rps: number
}

export interface CollaboratorInteraction {
  id: string
  token: string
  interaction_type: 'dns' | 'http' | 'https'
  source_ip: string
  received_at: string
  raw_payload: string | null
}

export type WsEvent =
  | ({ type: 'request.captured' } & NyxRequest)
  | { type: 'response.received'; request_id: string; status: number; headers: Record<string, string>; body: string | null; size_bytes: number; response_time_ms: number }
  | ({ type: 'finding.created' } & NyxFinding)
  | { type: 'fuzz.progress'; job_id: string; completed: number; total: number; last_payload: string }
  | { type: 'collaborator.hit'; token: string; interaction_type: string; source_ip: string }
  | { type: 'interceptor.request.paused'; item_id: string; request_id: string; method: string; url: string; headers: Record<string, string>; body: string | null }
  | { type: 'interceptor.response.paused'; item_id: string; request_id: string; status: number; headers: Record<string, string>; body: string | null }
  | { type: 'automation.url_discovered'; url: string; source: string }
  | { type: 'automation.scan_started'; url: string; checks_count: number }

import { apiClient } from '../client'
import { SessionHandlingRule, CookieEntry } from '../../types'

export async function fetchSessionRules(): Promise<SessionHandlingRule[]> {
  const { data } = await apiClient.get<SessionHandlingRule[]>('/api/session/rules')
  return data
}

export async function createSessionRule(rule: Partial<SessionHandlingRule>): Promise<SessionHandlingRule> {
  const { data } = await apiClient.post<SessionHandlingRule>('/api/session/rules', rule)
  return data
}

export async function updateSessionRule(id: string, rule: Partial<SessionHandlingRule>): Promise<SessionHandlingRule> {
  const { data } = await apiClient.put<SessionHandlingRule>(`/api/session/rules/${id}`, rule)
  return data
}

export async function updateMacroSteps(id: string, steps: unknown[]): Promise<SessionHandlingRule> {
  // Macro steps are stored in rule.config.requests — patch via the standard rule update endpoint
  const { data } = await apiClient.put<SessionHandlingRule>(`/api/session/rules/${id}`, {
    config: { requests: steps }
  })
  return data
}

export async function deleteSessionRule(id: string): Promise<void> {
  await apiClient.delete(`/api/session/rules/${id}`)
}

export async function fetchCookies(domain?: string): Promise<CookieEntry[]> {
  const { data } = await apiClient.get<CookieEntry[]>('/api/session/cookies', { params: { domain } })
  return data
}

export async function addCookie(cookie: Partial<CookieEntry>): Promise<CookieEntry> {
  const { data } = await apiClient.post<CookieEntry>('/api/session/cookies', cookie)
  return data
}

export async function deleteCookie(id: string): Promise<void> {
  await apiClient.delete(`/api/session/cookies/${id}`)
}

export async function runMacro(ruleId: string): Promise<{ results: unknown[] }> {
  const rules = await fetchSessionRules()
  const rule = rules.find(r => r.id === ruleId)
  if (!rule) throw new Error('Rule not found')
  const requests = (rule.config?.requests as any[]) || []
  const { data } = await apiClient.post('/api/session/macros/run', {
    session_id: rule.session_id,
    requests,
  })
  return data
}

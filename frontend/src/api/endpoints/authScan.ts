import { apiClient } from '../client'

export interface AuthProfile {
  id?: string; name: string; login_url: string; check_url: string
  check_pattern: string; steps: any[]; headers: Record<string, string>
}

export async function listAuthProfiles(): Promise<AuthProfile[]> {
  const r = await apiClient.get('/api/auth/profiles')
  return r.data
}

export async function createAuthProfile(p: AuthProfile): Promise<AuthProfile> {
  const r = await apiClient.post('/api/auth/profiles', p)
  return r.data
}

export async function updateAuthProfile(id: string, p: AuthProfile): Promise<AuthProfile> {
  const r = await apiClient.put(`/api/auth/profiles/${id}`, p)
  return r.data
}

export async function deleteAuthProfile(id: string): Promise<void> {
  await apiClient.delete(`/api/auth/profiles/${id}`)
}

export async function recordLogin(sessionId: string, loginUrl?: string): Promise<{ steps: any[]; message: string; captured_count: number }> {
  const r = await apiClient.post('/api/auth/login/record', { session_id: sessionId, login_url: loginUrl })
  return r.data
}

export async function runAuthScan(profileId: string, targetUrl: string, params?: string[]): Promise<any> {
  const r = await apiClient.post('/api/auth/scan', { profile_id: profileId, target_url: targetUrl, params: params || [] })
  return r.data
}

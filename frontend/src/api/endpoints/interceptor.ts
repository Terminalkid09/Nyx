import { apiClient } from '../client'
import { InterceptorRule, InterceptedItem } from '../../types'

export async function fetchInterceptorRules(): Promise<InterceptorRule[]> {
  const { data } = await apiClient.get<InterceptorRule[]>('/api/interceptor/rules')
  return data
}

export async function createInterceptorRule(rule: Partial<InterceptorRule>): Promise<InterceptorRule> {
  const { data } = await apiClient.post<InterceptorRule>('/api/interceptor/rules', rule)
  return data
}

export async function updateInterceptorRule(id: string, rule: Partial<InterceptorRule>): Promise<InterceptorRule> {
  const { data } = await apiClient.put<InterceptorRule>(`/api/interceptor/rules/${id}`, rule)
  return data
}

export async function deleteInterceptorRule(id: string): Promise<void> {
  await apiClient.delete(`/api/interceptor/rules/${id}`)
}

export async function fetchInterceptorStatus(): Promise<{ enabled: boolean }> {
  const { data } = await apiClient.get('/api/interceptor/status')
  return data
}

export async function toggleInterceptor(): Promise<{ enabled: boolean }> {
  const { data } = await apiClient.post('/api/interceptor/toggle')
  return data
}

export async function fetchPausedItems(): Promise<InterceptedItem[]> {
  const { data } = await apiClient.get<InterceptedItem[]>('/api/interceptor/paused')
  return data
}

export async function forwardItem(itemId: string, modifications?: { method?: string; url?: string; headers?: Record<string, string>; body?: string }): Promise<void> {
  await apiClient.post(`/api/interceptor/forward/${itemId}`, modifications || {})
}

export async function dropItem(itemId: string): Promise<void> {
  await apiClient.post(`/api/interceptor/drop/${itemId}`)
}

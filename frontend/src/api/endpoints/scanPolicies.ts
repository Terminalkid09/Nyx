import { apiClient } from '../client'

export interface ScanPolicy {
  id: string; name: string; description: string; priority: number
  config: Record<string, any>
}

export async function listPolicies(): Promise<ScanPolicy[]> {
  const r = await apiClient.get('/api/scan-policies')
  return r.data
}

export async function createPolicy(p: any): Promise<ScanPolicy> {
  const r = await apiClient.post('/api/scan-policies', p)
  return r.data
}

export async function getPolicy(id: string): Promise<ScanPolicy> {
  const r = await apiClient.get(`/api/scan-policies/${id}`)
  return r.data
}

export async function updatePolicy(id: string, data: any): Promise<ScanPolicy> {
  const r = await apiClient.put(`/api/scan-policies/${id}`, data)
  return r.data
}

export async function deletePolicy(id: string): Promise<void> {
  await apiClient.delete(`/api/scan-policies/${id}`)
}

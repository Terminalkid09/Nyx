import { apiClient } from '../client'

export interface RoEProfile {
  id: string
  name: string
  targets: string[]
  exclusions: string[]
  window_start: string | null
  window_end: string | null
  max_rps: number
  signature: string
  signature_valid: boolean
  active: boolean
  created_at: string | null
}

export interface RoEInput {
  name: string
  targets: string[]
  exclusions: string[]
  window_start: string | null
  window_end: string | null
  max_rps: number
}

export async function listRoEProfiles(): Promise<RoEProfile[]> {
  const { data } = await apiClient.get<RoEProfile[]>('/api/roe')
  return data
}

export async function createRoEProfile(input: RoEInput): Promise<RoEProfile> {
  const { data } = await apiClient.post<RoEProfile>('/api/roe', input)
  return data
}

export async function updateRoEProfile(id: string, input: RoEInput): Promise<RoEProfile> {
  const { data } = await apiClient.put<RoEProfile>(`/api/roe/${id}`, input)
  return data
}

export async function deleteRoEProfile(id: string): Promise<void> {
  await apiClient.delete(`/api/roe/${id}`)
}

export async function setRoEProfileActive(id: string, active: boolean): Promise<RoEProfile> {
  const action = active ? 'activate' : 'deactivate'
  const { data } = await apiClient.post<RoEProfile>(`/api/roe/${id}/${action}`)
  return data
}

export async function verifyRoEProfile(id: string): Promise<{ id: string; signature_valid: boolean }> {
  const { data } = await apiClient.post<{ id: string; signature_valid: boolean }>(
    `/api/roe/${id}/verify`,
  )
  return data
}

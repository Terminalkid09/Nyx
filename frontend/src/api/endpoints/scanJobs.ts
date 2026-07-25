import { apiClient } from '../client'
import { ScanJob } from '../../types'

export async function fetchScanJobs(): Promise<ScanJob[]> {
  const { data } = await apiClient.get<ScanJob[]>('/api/scan-jobs')
  return data
}

export async function createScanJob(job: { session_id?: string; scan_type: string; target_url?: string; priority?: number; config?: Record<string, unknown> }): Promise<ScanJob> {
  const { data } = await apiClient.post<ScanJob>('/api/scan-jobs', job)
  return data
}

export async function getScanJob(id: string): Promise<ScanJob> {
  const { data } = await apiClient.get<ScanJob>(`/api/scan-jobs/${id}`)
  return data
}

export async function startScanJob(id: string): Promise<ScanJob> {
  const { data } = await apiClient.post<ScanJob>(`/api/scan-jobs/${id}/start`)
  return data
}

export async function cancelScanJob(id: string): Promise<ScanJob> {
  const { data } = await apiClient.post<ScanJob>(`/api/scan-jobs/${id}/cancel`)
  return data
}

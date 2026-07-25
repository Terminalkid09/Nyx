import { apiClient } from '../client'

export interface MitmStatus {
  active: boolean
  arp_spoofing: boolean
  dns_spoofing: boolean
  target_ip: string | null
  gateway_ip: string | null
  admin_mode: boolean
}

export interface MitmStartRequest {
  target_ip: string
  gateway_ip: string
  enable_dns_spoof: boolean
}

export async function getMitmStatus(): Promise<MitmStatus> {
  const { data } = await apiClient.get('/api/mitm/status')
  return data
}

export async function startMitm(req: MitmStartRequest): Promise<void> {
  await apiClient.post('/api/mitm/start', req)
}

export async function stopMitm(): Promise<{ status: string }> {
  const { data } = await apiClient.post('/api/mitm/stop')
  return data
}

export async function getCaCertUrl(): Promise<string> {
  return '/api/ca-certificate'
}

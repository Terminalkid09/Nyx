import { apiClient } from '../client'

export interface MitmStatus {
  active: boolean
  arp_spoofing: boolean
  dns_spoofing: boolean
  target_ips: string[]
  gateway_ip: string | null
  admin_mode: boolean
  proxy_mode?: string | null
  redirect_active?: boolean
  captured_flows?: number
  last_traffic_seen?: string | null
  local_ip?: string | null
  proxy_host?: string | null
  proxy_port?: number | null
  tls_mitm?: boolean
}

export interface NetworkDevice {
  ip: string
  mac: string | null
  hostname: string | null
  vendor: string | null
  is_local: boolean
}

export interface MitmStartRequest {
  target_ips: string[]
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

export async function scanNetwork(): Promise<NetworkDevice[]> {
  const { data } = await apiClient.get('/api/mitm/scan-network')
  return data
}

export async function getCaCertUrl(): Promise<string> {
  return '/api/ca-certificate'
}

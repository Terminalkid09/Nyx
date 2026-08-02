import { apiClient } from '../client'

export interface ProxySettings {
  host: string; port: number; mode: string
}

export interface AllSettings {
  proxy: ProxySettings; api_host: string; api_port: number
}

export async function getAllSettings(): Promise<AllSettings> {
  const r = await apiClient.get('/api/settings/')
  return r.data
}

export async function getProxySettings(): Promise<ProxySettings> {
  const r = await apiClient.get('/api/settings/proxy')
  return r.data
}

export async function updateProxySettings(s: ProxySettings): Promise<ProxySettings> {
  const r = await apiClient.put('/api/settings/proxy', s)
  return r.data
}

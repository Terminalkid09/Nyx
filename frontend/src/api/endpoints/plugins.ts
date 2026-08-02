import { apiClient } from '../client'

export interface PluginItem {
  id: string; name: string; path: string; enabled: boolean
  hook_type: string; description: string | null; version: string
  config: Record<string, any>; created_at: string
}

export async function listPlugins(): Promise<PluginItem[]> {
  const r = await apiClient.get('/api/plugins')
  return r.data
}

export async function registerPlugin(data: { name: string; path: string; hook_type?: string; description?: string; version?: string; config?: any }): Promise<PluginItem> {
  const r = await apiClient.post('/api/plugins', data)
  return r.data
}

export async function togglePlugin(id: string): Promise<PluginItem> {
  const r = await apiClient.post(`/api/plugins/${id}/toggle`)
  return r.data
}

export async function deletePlugin(id: string): Promise<void> {
  await apiClient.delete(`/api/plugins/${id}`)
}

export async function reloadPlugins(): Promise<{ loaded: number; failed: number; total: number }> {
  const r = await apiClient.post('/api/plugins/reload')
  return r.data
}

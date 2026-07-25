import { apiClient } from '../client'
import { Plugin } from '../../types'

export async function fetchPlugins(): Promise<Plugin[]> {
  const { data } = await apiClient.get<Plugin[]>('/api/plugins')
  return data
}

export async function registerPlugin(plugin: { name: string; path: string; hook_type: string }): Promise<Plugin> {
  const { data } = await apiClient.post<Plugin>('/api/plugins', plugin)
  return data
}

export async function updatePlugin(id: string, plugin: Partial<Plugin>): Promise<Plugin> {
  const { data } = await apiClient.put<Plugin>(`/api/plugins/${id}`, plugin)
  return data
}

export async function deletePlugin(id: string): Promise<void> {
  await apiClient.delete(`/api/plugins/${id}`)
}

export async function togglePlugin(id: string): Promise<Plugin> {
  const { data } = await apiClient.post<Plugin>(`/api/plugins/${id}/toggle`)
  return data
}

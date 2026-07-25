import { apiClient } from '../client'
import { Project } from '../../types'

export async function fetchProjects(): Promise<Project[]> {
  const { data } = await apiClient.get<Project[]>('/api/projects')
  return data
}

export async function createProject(project: { name: string; description?: string; session_id?: string }): Promise<Project> {
  const { data } = await apiClient.post<Project>('/api/projects', project)
  return data
}

export async function updateProject(id: string, project: Partial<Project>): Promise<Project> {
  const { data } = await apiClient.put<Project>(`/api/projects/${id}`, project)
  return data
}

export async function deleteProject(id: string): Promise<void> {
  await apiClient.delete(`/api/projects/${id}`)
}

export async function exportProject(id: string): Promise<Blob> {
  const { data } = await apiClient.post(`/api/projects/${id}/export`, {}, { responseType: 'blob' })
  return data
}

export async function importProject(data: Record<string, unknown>): Promise<Project> {
  const { data: result } = await apiClient.post<Project>('/api/projects/import', data)
  return result
}

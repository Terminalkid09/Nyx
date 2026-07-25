import { apiClient } from '../client'
import { ComparerItem, DiffResult } from '../../types'

export async function fetchComparerItems(): Promise<ComparerItem[]> {
  const { data } = await apiClient.get<ComparerItem[]>('/api/comparer/items')
  return data
}

export async function createComparerItem(item: { left_request_id?: string; right_request_id?: string; left_content?: string; right_content?: string; left_label?: string; right_label?: string }): Promise<ComparerItem> {
  const { data } = await apiClient.post<ComparerItem>('/api/comparer/items', item)
  return data
}

export async function deleteComparerItem(id: string): Promise<void> {
  await apiClient.delete(`/api/comparer/items/${id}`)
}

export async function compareItem(id: string): Promise<DiffResult> {
  const { data } = await apiClient.get<DiffResult>(`/api/comparer/compare/${id}`)
  return data
}

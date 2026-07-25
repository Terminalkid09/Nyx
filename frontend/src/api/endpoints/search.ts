import { apiClient } from '../client'
import { SearchResult } from '../../types'

export async function globalSearch(q: string, type?: string, page?: number): Promise<{ items: SearchResult[]; total: number }> {
  const { data } = await apiClient.get('/api/search', { params: { q, type, page, per_page: 50 } })
  return data
}

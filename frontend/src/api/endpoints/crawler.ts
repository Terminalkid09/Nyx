import { apiClient } from '../client'

export interface CrawlJob {
  id: string
  start_url: string
  status: 'pending' | 'running' | 'completed' | 'stopped' | 'failed'
  progress: number
  max_pages: number
  discovered_urls: string[]
  discovered_forms: any[]
  created_at: string
}

export async function startCrawl(config: {
  start_url: string
  max_depth?: number
  max_pages?: number
  scope_include?: string[]
  scope_exclude?: string[]
  form_fill_config?: Record<string, string>
  login_macro?: { url: string; method: string; body?: string; headers?: Record<string, string> }[]
  headers?: Record<string, string>
  respect_robots_txt?: boolean
}): Promise<CrawlJob> {
  const { data } = await apiClient.post('/api/crawler/start', config)
  return data
}

export async function getCrawlStatus(jobId: string): Promise<CrawlJob> {
  const { data } = await apiClient.get(`/api/crawler/status/${jobId}`)
  return data
}

export async function stopCrawl(jobId: string): Promise<void> {
  await apiClient.post(`/api/crawler/stop/${jobId}`)
}

export async function listCrawlJobs(): Promise<CrawlJob[]> {
  const { data } = await apiClient.get('/api/crawler/jobs')
  return data
}

export async function getCrawlForms(jobId: string): Promise<any[]> {
  const { data } = await apiClient.get(`/api/crawler/forms/${jobId}`)
  return data
}

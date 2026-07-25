import { apiClient } from '../client'

export async function fetchDiscoveredUrls(): Promise<{ url: string; source: string; timestamp: string; host: string }[]> {
  const { data } = await apiClient.get('/api/automation/discovered')
  return data
}

export async function fetchPendingScans(): Promise<{ url: string; priority: number }[]> {
  const { data } = await apiClient.get('/api/automation/pending')
  return data
}

export async function updateAutoScanConfig(config: {
  auto_active_scan?: boolean
  max_concurrent?: number
  scan_delay_ms?: number
}): Promise<{ auto_active_scan: boolean; max_concurrent: number; scan_delay_ms: number }> {
  const { data } = await apiClient.post('/api/automation/config', config)
  return data
}

export async function getAutoScanConfig(): Promise<{
  auto_active_scan: boolean
  max_concurrent: number
  scan_delay_ms: number
}> {
  const { data } = await apiClient.get('/api/automation/config')
  return data
}

export interface WebhookConfig {
  id?: string
  name: string
  type: string
  url: string
  enabled: boolean
  events: string[]
}

export async function fetchWebhooks(): Promise<WebhookConfig[]> {
  const { data } = await apiClient.get('/api/automations/webhooks')
  return data
}

export async function createWebhook(config: WebhookConfig): Promise<WebhookConfig> {
  const { data } = await apiClient.post('/api/automations/webhooks', config)
  return data
}

export async function updateWebhook(id: string, config: Partial<WebhookConfig>): Promise<WebhookConfig> {
  const { data } = await apiClient.put(`/api/automations/webhooks/${id}`, config)
  return data
}

export async function deleteWebhook(id: string): Promise<void> {
  await apiClient.delete(`/api/automations/webhooks/${id}`)
}

export async function testWebhook(id: string): Promise<void> {
  await apiClient.post(`/api/automations/webhooks/test/${id}`)
}

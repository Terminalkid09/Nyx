import { apiClient } from '../client'

export interface Webhook {
  id: string; name: string; type: string; url: string; enabled: boolean; events: string[]
}

export interface Schedule {
  id: string; name: string; target_url: string; cron: string; enabled: boolean; config: any; template_id: string | null
}

export interface Template {
  id: string; name: string; description: string; config: any
}

export interface Report {
  filename: string; title: string; created_at: string
}

export async function listWebhooks(): Promise<Webhook[]> {
  const r = await apiClient.get('/api/automations/webhooks')
  return r.data
}

export async function createWebhook(data: any): Promise<Webhook> {
  const r = await apiClient.post('/api/automations/webhooks', data)
  return r.data
}

export async function updateWebhook(id: string, data: any): Promise<Webhook> {
  const r = await apiClient.put(`/api/automations/webhooks/${id}`, data)
  return r.data
}

export async function deleteWebhook(id: string): Promise<void> {
  await apiClient.delete(`/api/automations/webhooks/${id}`)
}

export async function testWebhook(id: string): Promise<void> {
  await apiClient.post(`/api/automations/webhooks/test/${id}`)
}

export async function listSchedules(): Promise<Schedule[]> {
  const r = await apiClient.get('/api/automations/schedules')
  return r.data
}

export async function createSchedule(data: any): Promise<Schedule> {
  const r = await apiClient.post('/api/automations/schedules', data)
  return r.data
}

export async function updateSchedule(id: string, data: any): Promise<Schedule> {
  const r = await apiClient.put(`/api/automations/schedules/${id}`, data)
  return r.data
}

export async function deleteSchedule(id: string): Promise<void> {
  await apiClient.delete(`/api/automations/schedules/${id}`)
}

export async function toggleSchedule(id: string): Promise<{ enabled: boolean }> {
  const r = await apiClient.post(`/api/automations/schedules/${id}/toggle`)
  return r.data
}

export async function listTemplates(): Promise<Template[]> {
  const r = await apiClient.get('/api/automations/templates')
  return r.data
}

export async function createTemplate(data: any): Promise<Template> {
  const r = await apiClient.post('/api/automations/templates', data)
  return r.data
}

export async function deleteTemplate(id: string): Promise<void> {
  await apiClient.delete(`/api/automations/templates/${id}`)
}

export async function listReports(): Promise<Report[]> {
  const r = await apiClient.get('/api/automations/reports')
  return r.data
}

export async function generateCSRF(url: string, method = 'POST', headers: any = {}, body = ''): Promise<{ html: string }> {
  const r = await apiClient.post('/api/automations/csrf-poc/generate', { url, method, headers, body })
  return r.data
}

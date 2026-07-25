import { apiClient } from '../client'

export async function fetchLiveAuditStatus() {
  const { data } = await apiClient.get('/api/live-audit/status')
  return data
}

export async function startLiveAudit() {
  const { data } = await apiClient.post('/api/live-audit/start')
  return data
}

export async function stopLiveAudit() {
  const { data } = await apiClient.post('/api/live-audit/stop')
  return data
}

export async function updateLiveAuditConfig(config: Record<string, any>) {
  const { data } = await apiClient.put('/api/live-audit/config', config)
  return data
}

export async function fetchLiveAuditConfig() {
  const { data } = await apiClient.get('/api/live-audit/config')
  return data
}

export async function clearAuditStats() {
  const { data } = await apiClient.post('/api/live-audit/clear-stats')
  return data
}

export async function clearAuditLog() {
  const { data } = await apiClient.post('/api/live-audit/clear-log')
  return data
}

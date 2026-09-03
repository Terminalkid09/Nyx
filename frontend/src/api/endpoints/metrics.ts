import { apiClient } from '../client'

export interface NyxMetrics {
  proxy_requests_total: number
  proxy_requests_https_total: number
  proxy_responses_total: number
  proxy_responses_2xx_total: number
  proxy_responses_4xx_total: number
  proxy_responses_5xx_total: number
  proxy_response_time_ms_last: number
  mitm_sessions_started_total: number
  mitm_sessions_active: number
  mitm_arp_spoofs_total: number
  mitm_dhcp_spoofs_total: number
  mitm_ndp_spoofs_total: number
  http_errors_5xx_total: number
  process_uptime_seconds: number
}

export async function getMetrics(): Promise<NyxMetrics> {
  const { data } = await apiClient.get('/metrics', {
    headers: { Accept: 'text/plain' },
    transformResponse: [(raw: string) => {
      const metrics: Record<string, number> = {}
      for (const line of raw.split('\n')) {
        if (line.startsWith('#') || !line.trim()) continue
        const parts = line.trim().split(/\s+/)
        if (parts.length >= 2) {
          const name = parts[0].replace(/^nyx_/, '')
          metrics[name] = parseFloat(parts[1]) || 0
        }
      }
      return metrics as unknown as NyxMetrics
    }],
  })
  return data
}

export async function getHealth() {
  const { data } = await apiClient.get('/health')
  return data
}
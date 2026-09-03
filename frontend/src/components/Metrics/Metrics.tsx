import { useState, useEffect } from 'react'
import { Activity, Clock, Server, Shield, Zap, AlertTriangle } from 'lucide-react'
import { getMetrics, getHealth, type NyxMetrics } from '../../api/endpoints/metrics'

function StatCard({ icon: Icon, label, value, color = 'text-gray-300', sub }: {
  icon: any
  label: string
  value: string | number
  color?: string
  sub?: string
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-3">
      <div className="flex items-center gap-2 mb-1">
        <Icon size={14} className="text-gray-500" />
        <span className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</span>
      </div>
      <div className={`text-lg font-bold ${color}`}>{value}</div>
      {sub && <div className="text-[10px] text-gray-600 mt-0.5">{sub}</div>}
    </div>
  )
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  const h = Math.floor(seconds / 3600)
  const m = Math.round((seconds % 3600) / 60)
  return `${h}h ${m}m`
}

export function Metrics() {
  const [metrics, setMetrics] = useState<NyxMetrics | null>(null)
  const [health, setHealth] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const load = async () => {
      try {
        const [m, h] = await Promise.all([getMetrics(), getHealth()])
        setMetrics(m)
        setHealth(h)
      } catch (e: any) {
        setError(e.response?.data?.detail || e.message)
      } finally {
        setLoading(false)
      }
    }
    load()
    const interval = setInterval(load, 5000) // refresh every 5s
    return () => clearInterval(interval)
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500 text-sm">
        Loading metrics…
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-4">
        <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>
      </div>
    )
  }

  const totalResponses = (metrics?.proxy_responses_2xx_total || 0) +
    (metrics?.proxy_responses_4xx_total || 0) +
    (metrics?.proxy_responses_5xx_total || 0)

  const errorRate = totalResponses > 0
    ? ((metrics?.proxy_responses_5xx_total || 0) / totalResponses * 100).toFixed(1)
    : '0.0'

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 flex items-center gap-2 text-sm font-medium text-gray-300">
        <Activity size={16} />
        <span>Metrics Dashboard</span>
        <span className="text-[10px] text-gray-600 ml-auto">Auto-refresh: 5s</span>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-6">
        {/* Health status */}
        <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${
          health?.status === 'ok'
            ? 'bg-green-950/20 border-green-900/30 text-green-400'
            : 'bg-yellow-950/20 border-yellow-900/30 text-yellow-400'
        }`}>
          <div className={`w-2 h-2 rounded-full ${health?.status === 'ok' ? 'bg-green-400' : 'bg-yellow-400'}`} />
          <span className="text-xs font-medium">Backend: {health?.status?.toUpperCase()}</span>
          <span className="text-[10px] text-gray-500 ml-auto">
            Uptime: {health?.uptime_sec ? formatUptime(health.uptime_sec) : '—'}
          </span>
          {health?.memory && (
            <span className="text-[10px] text-gray-500">
              Memory: {health.memory.rss_mb} MB RSS
            </span>
          )}
        </div>

        {/* Proxy stats */}
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">Proxy</h4>
          <div className="grid grid-cols-4 gap-2">
            <StatCard
              icon={Activity}
              label="Total Requests"
              value={metrics?.proxy_requests_total || 0}
              sub={`${metrics?.proxy_requests_https_total || 0} HTTPS`}
            />
            <StatCard
              icon={Activity}
              label="Total Responses"
              value={totalResponses}
              sub={`${metrics?.proxy_responses_2xx_total || 0} 2xx`}
            />
            <StatCard
              icon={AlertTriangle}
              label="4xx Errors"
              value={metrics?.proxy_responses_4xx_total || 0}
              color="text-yellow-400"
            />
            <StatCard
              icon={AlertTriangle}
              label="5xx Errors"
              value={metrics?.proxy_responses_5xx_total || 0}
              color="text-red-400"
              sub={`${errorRate}% error rate`}
            />
          </div>
        </div>

        {/* MITM stats */}
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">MITM</h4>
          <div className="grid grid-cols-4 gap-2">
            <StatCard
              icon={Shield}
              label="Sessions Started"
              value={metrics?.mitm_sessions_started_total || 0}
            />
            <StatCard
              icon={Shield}
              label="Active Sessions"
              value={metrics?.mitm_sessions_active || 0}
              color={metrics?.mitm_sessions_active ? 'text-green-400' : 'text-gray-500'}
            />
            <StatCard
              icon={Zap}
              label="ARP Spoofs"
              value={metrics?.mitm_arp_spoofs_total || 0}
            />
            <StatCard
              icon={Zap}
              label="DHCP Spoofs"
              value={metrics?.mitm_dhcp_spoofs_total || 0}
            />
          </div>
        </div>

        {/* Process info */}
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-2">Process</h4>
          <div className="grid grid-cols-3 gap-2">
            <StatCard
              icon={Clock}
              label="Uptime"
              value={formatUptime(metrics?.process_uptime_seconds || 0)}
            />
            <StatCard
              icon={Server}
              label="Database"
              value={health?.database?.ok ? 'OK' : 'ERROR'}
              color={health?.database?.ok ? 'text-green-400' : 'text-red-400'}
              sub={health?.database?.error || ''}
            />
            <StatCard
              icon={Server}
              label="Proxy"
              value={health?.proxy?.ok ? 'OK' : 'ERROR'}
              color={health?.proxy?.ok ? 'text-green-400' : 'text-red-400'}
              sub={`${health?.proxy?.host}:${health?.proxy?.port}`}
            />
          </div>
        </div>
      </div>
    </div>
  )
}
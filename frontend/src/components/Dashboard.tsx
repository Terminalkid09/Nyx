import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  PieChart, Pie, Cell, Tooltip as ReTooltip, ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  BarChart, Bar, Legend,
} from 'recharts'
import {
  Shield, Activity, Globe, Monitor, Plus, Play, AlertTriangle,
  Download, XCircle, RefreshCw, Zap, Webhook, Calendar, FileText,
  TrendingUp, Target, Bug, Server, ExternalLink, Clock, CheckCircle, HelpCircle,
} from 'lucide-react'
import { apiClient } from '../api/client'
import { UnifiedProgress } from './UnifiedProgress'
import { OnboardingTutorial } from './OnboardingTutorial'

interface DashboardStats {
  total_findings: number
  findings_by_severity: Record<string, number>
  trends: Array<{ date: string; critical: number; high: number; medium: number; low: number; info: number }>
  top_endpoints: Array<{ path: string; count: number }>
  vuln_breakdown: Array<{ type: string; count: number }>
  scan_history: Array<{
    id: string; target: string; status: string; progress: number
    total_checks: number; passed_checks: number; failed_checks: number; created_at: string
  }>
  active_scans: number
  proxy_requests_today: number
  total_endpoints: number
  recent_findings: Array<{
    id: string; title: string; severity: string; endpoint: string; module: string; created_at: string
  }>
}

const SEVERITY_CONFIG: Record<string, { color: string; fill: string; bg: string; dot: string }> = {
  critical: { color: '#ef4444', fill: '#ef4444', bg: 'bg-red-500/10 text-red-400', dot: 'bg-red-500' },
  high:     { color: '#f97316', fill: '#f97316', bg: 'bg-orange-500/10 text-orange-400', dot: 'bg-orange-500' },
  medium:   { color: '#eab308', fill: '#eab308', bg: 'bg-yellow-500/10 text-yellow-400', dot: 'bg-yellow-500' },
  low:      { color: '#22c55e', fill: '#22c55e', bg: 'bg-green-500/10 text-green-400', dot: 'bg-green-500' },
  info:     { color: '#3b82f6', fill: '#3b82f6', bg: 'bg-blue-500/10 text-blue-400', dot: 'bg-blue-500' },
}

function AnimatedStat({ label, value, icon: Icon, color, subtitle }: {
  label: string; value: number; icon: any; color: string; subtitle?: string
}) {
  return (
    <div className="bg-gray-900/80 border border-gray-700/50 rounded-lg p-3 hover:border-gray-600 transition-colors">
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</span>
        <Icon size={16} style={{ color }} />
      </div>
      <div className="text-2xl font-bold text-gray-100 font-mono">{value.toLocaleString()}</div>
      {subtitle && <div className="text-[10px] text-gray-500 mt-0.5">{subtitle}</div>}
    </div>
  )
}

function StatCard({ label, value, icon: Icon, color, onClick }: {
  label: string; value: string | number; icon: any; color: string; onClick?: () => void
}) {
  return (
    <button
      onClick={onClick}
      className="bg-gray-900/80 border border-gray-700/50 rounded-lg p-3 hover:border-gray-600 transition-colors text-left w-full"
    >
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</span>
        <Icon size={14} style={{ color }} />
      </div>
      <div className="text-lg font-bold font-mono text-gray-100">
        {value}
      </div>
    </button>
  )
}

export function Dashboard() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [generating, setGenerating] = useState(false)
  const [showTutorial, setShowTutorial] = useState(() => {
    return localStorage.getItem('nyx_tutorial_dismissed') !== 'true'
  })
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const loadData = () => {
    apiClient.get('/api/dashboard/stats')
      .then(r => { setStats(r.data); setError('') })
      .catch(err => setError(err.response?.data?.detail || err.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
    pollingRef.current = setInterval(loadData, 8000)
    return () => { if (pollingRef.current) clearInterval(pollingRef.current) }
  }, [])

  const handleGenerateReport = async () => {
    setGenerating(true)
    try {
      const response = await apiClient.post('/api/automations/reports/generate', {}, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `nyx-report-${Date.now()}.pdf`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally { setGenerating(false) }
  }

  if (loading) {
    return (
      <div className="flex flex-col h-full">
        <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
          <Shield size={16} className="text-purple-500" /> <span>Dashboard</span>
        </div>
        <div className="flex-1 flex items-center justify-center">
          <RefreshCw size={24} className="text-purple-500 animate-spin" />
        </div>
      </div>
    )
  }

  if (!stats) {
    return (
      <div className="flex flex-col h-full">
        <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
          <Shield size={16} className="text-purple-500" /> <span>Dashboard</span>
        </div>
        <div className="flex-1 flex flex-col items-center justify-center p-4">
          <AlertTriangle size={48} className="text-red-500 mb-4" />
          <h2 className="text-xl font-bold text-gray-200 mb-2">Failed to load Dashboard</h2>
          <div className="text-red-400 bg-red-400/10 p-3 rounded text-sm max-w-md text-center break-words">
            {error || 'Unable to connect to the Nyx backend API.'}
          </div>
          <button onClick={loadData} className="mt-4 flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded transition-colors">
            <RefreshCw size={16} /> Retry
          </button>
        </div>
      </div>
    )
  }

  const s = stats
  const severityPieData = Object.entries(SEVERITY_CONFIG)
    .filter(([k]) => (s.findings_by_severity[k] || 0) > 0)
    .map(([k, v]) => ({ name: k, value: s.findings_by_severity[k] || 0, fill: v.fill }))

  const activePipelines = s.scan_history.filter(j => j.status === 'running')
  const totalFindings = Object.values(s.findings_by_severity).reduce((a, b) => a + b, 0)

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-purple-500" />
          <span>Dashboard</span>
          {activePipelines.length > 0 && (
            <span className="text-[10px] text-purple-400 animate-pulse ml-2">
              {activePipelines.length} scan{activePipelines.length > 1 ? 's' : ''} active
            </span>
          )}
        </div>
        <div className="flex items-center gap-4">
          <button 
            onClick={() => {
              const newState = !showTutorial
              setShowTutorial(newState)
              localStorage.setItem('nyx_tutorial_dismissed', (!newState).toString())
            }}
            className="flex items-center gap-1 text-[10px] text-purple-400 hover:text-purple-300 transition-colors"
          >
            <HelpCircle size={12} />
            {showTutorial ? 'Hide Tutorial' : 'Show Tutorial'}
          </button>
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-gray-600">Auto-refresh 8s</span>
            <button onClick={loadData} className="p-1 text-gray-500 hover:text-gray-300">
              <RefreshCw size={12} />
            </button>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>}

        {showTutorial && <OnboardingTutorial onClose={() => {
          setShowTutorial(false)
          localStorage.setItem('nyx_tutorial_dismissed', 'true')
        }} />}

        {/* Quick Actions */}
        <div className="bg-gray-900/60 border border-gray-700/50 rounded-lg p-3 overflow-x-auto">
          <div className="flex gap-2 min-w-max">
            {(window as any).nyxDesktop && (
              <button onClick={() => (window as any).nyxDesktop.launchBrowser()}
                className="flex flex-col items-center gap-1 bg-orange-600/20 hover:bg-orange-600/30 border border-orange-500/30 rounded-lg p-2 transition-colors relative shrink-0 w-20 h-16">
                <Globe size={16} className="text-orange-400" />
                <span className="text-[10px] text-orange-300 font-bold whitespace-nowrap">Browser</span>
              </button>
            )}
            {!(window as any).nyxDesktop && (
              <button onClick={() => alert('Per catturare traffico:\n1. Configura il proxy del browser su 127.0.0.1:8080\n   Oppure esegui: cd frontend && npm run build\n   Poi: cd desktop && npm start\n2. Naviga su un sito HTTP (es. testfire.net)\n3. Il traffico apparirà in Proxy Log')}
                className="flex flex-col items-center gap-1 bg-orange-600/20 hover:bg-orange-600/30 border border-orange-500/30 rounded-lg p-2 transition-colors relative shrink-0 w-20 h-16">
                <Globe size={16} className="text-orange-400" />
                <span className="text-[10px] text-orange-300 font-bold whitespace-nowrap">Proxy</span>
              </button>
            )}
            {[
              { to: '/scan/new', icon: Plus, label: 'New Scan', color: 'text-purple-400' },
              { to: '/proxy', icon: Play, label: 'Proxy', color: 'text-blue-400' },
              { to: '/scanner', icon: Bug, label: 'Findings', color: 'text-red-400' },
              { to: '/repeater', icon: ExternalLink, label: 'Repeater', color: 'text-green-400' },
              { to: '/fuzzer', icon: Target, label: 'Fuzzer', color: 'text-yellow-400' },
              { to: '/automation', icon: Webhook, label: 'Automation', color: 'text-cyan-400' },
              { to: '/live-audit', icon: Activity, label: 'Live', color: 'text-purple-400' },
            ].map(btn => (
              <button key={btn.to} onClick={() => navigate(btn.to)}
                className="flex flex-col items-center gap-1 bg-gray-800 hover:bg-gray-700 rounded-lg p-2 transition-colors shrink-0 w-20 h-16">
                <btn.icon size={16} className={btn.color} />
                <span className="text-[10px] text-gray-400 whitespace-nowrap">{btn.label}</span>
              </button>
            ))}
            <button onClick={handleGenerateReport} disabled={generating}
              className="flex flex-col items-center gap-1 bg-gray-800 hover:bg-gray-700 rounded-lg p-2 transition-colors disabled:opacity-50 shrink-0 w-20 h-16">
              <Download size={16} className="text-purple-400" />
              <span className="text-[10px] text-gray-400">{generating ? '...' : 'Report'}</span>
            </button>
          </div>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <AnimatedStat label="Total Findings" value={totalFindings} icon={AlertTriangle} color="#a855f7"
            subtitle={`${s.findings_by_severity.critical || 0} critical`} />
          <AnimatedStat label="Active Scans" value={s.active_scans} icon={Zap} color="#22d3ee"
            subtitle={s.active_scans > 0 ? 'Running' : 'Idle'} />
          <AnimatedStat label="Endpoints" value={s.total_endpoints} icon={Server} color="#22c55e" />
          <AnimatedStat label="Proxy Today" value={s.proxy_requests_today} icon={Globe} color="#3b82f6" />
          <StatCard label="Scan History" value={`${s.scan_history.length} total`} icon={Clock} color="#f59e0b" />
        </div>

        {/* Active Scans */}
        {activePipelines.length > 0 && (
          <div className="bg-gray-900/80 border border-gray-700/50 rounded-lg p-3">
            <div className="text-xs font-medium text-gray-400 mb-2 flex items-center gap-2">
              <Zap size={14} className="text-purple-400" />
              Active Scans <span className="text-[10px] text-purple-400 animate-pulse">Live</span>
            </div>
            <div className="space-y-2">
              {activePipelines.slice(0, 5).map(p => (
                <div key={p.id} className="bg-gray-800/80 rounded p-2.5">
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <div className="w-2 h-2 rounded-full bg-purple-500 animate-pulse" />
                      <span className="text-xs font-mono text-gray-200 truncate">{p.target || 'Unknown target'}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 text-[10px] text-gray-500">
                    <span>Checks: {p.passed_checks}/{p.total_checks}</span>
                    <span>Failed: {p.failed_checks}</span>
                    <span className="ml-auto">{p.progress}%</span>
                  </div>
                  <div className="mt-1 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                    <div className="h-full bg-gradient-to-r from-purple-600 to-purple-400 rounded-full transition-all duration-500"
                      style={{ width: `${Math.min(p.progress, 100)}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Severity Donut */}
          <div className="bg-gray-900/80 border border-gray-700/50 rounded-lg p-3">
            <div className="text-xs font-medium text-gray-400 mb-2">Findings by Severity</div>
            {severityPieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={severityPieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70}
                    dataKey="value" paddingAngle={2}>
                    {severityPieData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} stroke="transparent" />
                    ))}
                  </Pie>
                  <ReTooltip
                    contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '6px', fontSize: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[180px] flex items-center justify-center text-xs text-gray-600">No findings yet</div>
            )}
            <div className="flex justify-center gap-3 mt-1">
              {Object.entries(SEVERITY_CONFIG).map(([k, v]) => (
                <div key={k} className="flex items-center gap-1">
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: v.fill }} />
                  <span className="text-[10px] text-gray-500">{s.findings_by_severity[k] || 0}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Trend Line */}
          <div className="bg-gray-900/80 border border-gray-700/50 rounded-lg p-3">
            <div className="text-xs font-medium text-gray-400 mb-2 flex items-center gap-2">
              <TrendingUp size={14} className="text-green-400" />
              14-Day Finding Trend
            </div>
            {s.trends.some(d => d.critical + d.high + d.medium + d.low > 0) ? (
              <ResponsiveContainer width="100%" height={180}>
                <LineChart data={s.trends}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                  <XAxis dataKey="date" tick={{ fontSize: 9, fill: '#6b7280' }}
                    tickFormatter={v => v.slice(5)} />
                  <YAxis tick={{ fontSize: 9, fill: '#6b7280' }} allowDecimals={false} />
                  <ReTooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '6px', fontSize: '12px' }} />
                  <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="medium" stroke="#eab308" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="low" stroke="#22c55e" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[180px] flex items-center justify-center text-xs text-gray-600">No trend data</div>
            )}
          </div>

          {/* Vuln Breakdown */}
          <div className="bg-gray-900/80 border border-gray-700/50 rounded-lg p-3">
            <div className="text-xs font-medium text-gray-400 mb-2 flex items-center gap-2">
              <Bug size={14} className="text-red-400" />
              Top Vulnerability Types
            </div>
            {s.vuln_breakdown.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={s.vuln_breakdown.slice(0, 8)} layout="vertical" margin={{ left: 0, right: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 9, fill: '#6b7280' }} allowDecimals={false} />
                  <YAxis type="category" dataKey="type" tick={{ fontSize: 8, fill: '#9ca3af' }}
                    width={80} tickFormatter={v => v.length > 12 ? v.slice(0, 12) + '...' : v} />
                  <ReTooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '6px', fontSize: '12px' }} />
                  <Bar dataKey="count" fill="#a855f7" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[180px] flex items-center justify-center text-xs text-gray-600">No data</div>
            )}
          </div>
        </div>

        {/* Bottom Row: Top Endpoints + Recent Findings */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-gray-900/80 border border-gray-700/50 rounded-lg p-3">
            <div className="text-xs font-medium text-gray-400 mb-2">Top Affected Endpoints</div>
            {s.top_endpoints.length > 0 ? (
              <div className="space-y-1">
                {s.top_endpoints.map((ep, i) => {
                  const maxCount = Math.max(...s.top_endpoints.map(e => e.count))
                  const pct = maxCount > 0 ? (ep.count / maxCount) * 100 : 0
                  return (
                    <div key={i} className="flex items-center gap-2">
                      <span className="text-[10px] text-gray-600 w-4 text-right">{i + 1}.</span>
                      <span className="text-[10px] font-mono text-gray-300 truncate flex-1">{ep.path}</span>
                      <span className="text-[10px] text-gray-500 w-8 text-right">{ep.count}</span>
                      <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                        <div className="h-full bg-purple-500/60 rounded-full" style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className="text-xs text-gray-600 py-4 text-center">No endpoints tracked</div>
            )}
          </div>
          <div className="bg-gray-900/80 border border-gray-700/50 rounded-lg p-3">
            <div className="text-xs font-medium text-gray-400 mb-2 flex items-center justify-between">
              <span>Recent Findings</span>
              <button onClick={() => navigate('/scanner')} className="text-[10px] text-purple-400 hover:text-purple-300">View All</button>
            </div>
            {s.recent_findings.length > 0 ? (
              <div className="space-y-1">
                {s.recent_findings.slice(0, 8).map(f => (
                  <div key={f.id} onClick={(e) => { if (!window.getSelection()?.toString()) navigate(`/scanner?finding=${f.id}`) }}
                    className="flex items-center gap-2 py-1.5 px-2 rounded hover:bg-gray-800/50 cursor-pointer transition-colors">
                    <div className={`w-2 h-2 rounded-full ${SEVERITY_CONFIG[f.severity]?.dot || 'bg-gray-500'}`} />
                    <span className={`text-[10px] px-1 rounded ${SEVERITY_CONFIG[f.severity]?.bg || 'text-gray-400'}`}>{f.severity}</span>
                    <span className="text-xs text-gray-200 font-mono truncate flex-1">{f.title}</span>
                    <span className="text-[10px] text-gray-600 truncate max-w-[100px]">{f.endpoint}</span>
                    <span className="text-[10px] text-gray-600">{new Date(f.created_at).toLocaleDateString()}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-gray-600 py-4 text-center">No findings yet</div>
            )}
          </div>
        </div>

        {/* Scan History */}
        {s.scan_history.length > 0 && (
          <div className="bg-gray-900/80 border border-gray-700/50 rounded-lg p-3">
            <div className="text-xs font-medium text-gray-400 mb-2">Recent Scan Jobs</div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500">
                    <th className="text-left px-2 py-1.5 font-medium">Target</th>
                    <th className="text-left px-2 py-1.5 font-medium">Status</th>
                    <th className="text-left px-2 py-1.5 font-medium">Progress</th>
                    <th className="text-right px-2 py-1.5 font-medium">Checks</th>
                    <th className="text-right px-2 py-1.5 font-medium">Date</th>
                  </tr>
                </thead>
                <tbody>
                  {s.scan_history.map(j => (
                    <tr key={j.id} className="border-b border-gray-800 hover:bg-gray-800/50">
                      <td className="px-2 py-1.5 font-mono text-gray-300 truncate max-w-[200px]">{j.target || 'Unknown'}</td>
                      <td className="px-2 py-1.5">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                          j.status === 'running' ? 'text-purple-400 bg-purple-500/10' :
                          j.status === 'completed' ? 'text-green-400 bg-green-500/10' :
                          j.status === 'failed' ? 'text-red-400 bg-red-500/10' :
                          'text-gray-400 bg-gray-500/10'
                        }`}>{j.status}</span>
                      </td>
                      <td className="px-2 py-1.5">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                            <div className="h-full bg-gradient-to-r from-purple-600 to-purple-400 rounded-full"
                              style={{ width: `${Math.min(j.progress, 100)}%` }} />
                          </div>
                          <span className="text-[10px] text-gray-500">{j.progress}%</span>
                        </div>
                      </td>
                      <td className="px-2 py-1.5 text-right text-gray-400">
                        <span className="text-green-400">{j.passed_checks}</span>
                        <span className="text-gray-600">/{j.total_checks}</span>
                      </td>
                      <td className="px-2 py-1.5 text-right text-gray-500 text-[10px]">
                        {new Date(j.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

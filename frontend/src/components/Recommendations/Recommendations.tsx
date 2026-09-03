import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Lightbulb, RefreshCw, X, ChevronRight, Bug, Zap, Shield, Search, FolderOpen, Globe } from 'lucide-react'
import { apiClient } from '../../api/client'

interface Recommendation {
  id: string; rule_id: string; label: string; description: string
  module: string; icon: string; priority: number
  finding: { id: string; cwe: string; severity: string; title: string; module: string }
  created_at: string; dismissed: boolean; executed: boolean
}

const MODULE_ICONS: Record<string, any> = {
  fuzzer: Zap, auto_exploit: Bug, active_scanner: Shield,
  triage: Search, crawler: Globe, content_discovery: FolderOpen,
}

const SEV_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-900/30 border-red-800',
  high: 'text-orange-400 bg-orange-900/30 border-orange-800',
  medium: 'text-yellow-400 bg-yellow-900/30 border-yellow-800',
  low: 'text-blue-400 bg-blue-900/30 border-blue-800',
}

export function Recommendations() {
  const navigate = useNavigate()
  const [recs, setRecs] = useState<Recommendation[]>([])
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState({ total: 0, by_rule: {} as Record<string, number>, by_module: {} as Record<string, number> })

  const fetch = async () => {
    try {
      const r = await apiClient.get('/api/recommendations')
      setRecs(r.data.recommendations || [])
      setStats(r.data.stats || { total: 0, by_rule: {}, by_module: {} })
    } catch {} finally { setLoading(false) }
  }
  useEffect(() => { fetch() }, [])

  const dismiss = async (id: string) => {
    try {
      await apiClient.post('/api/recommendations/dismiss', { rec_id: id })
      setRecs(prev => prev.filter(r => r.id !== id))
    } catch {}
  }

  const execute = async (rec: Recommendation) => {
    try {
      const r = await apiClient.post('/api/recommendations/execute', { rec_id: rec.id })
      setRecs(prev => prev.filter(r => r.id !== rec.id))
      const action = r.data.action
      if (action?.redirect) {
        navigate(action.redirect, {
          state: {
            ...(action.params || {}),
            finding: rec.finding,
          },
        })
      }
    } catch {}
  }

  const groupByModule = (items: Recommendation[]) => {
    const groups: Record<string, Recommendation[]> = {}
    for (const r of items) {
      if (!groups[r.module]) groups[r.module] = []
      groups[r.module].push(r)
    }
    return groups
  }

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6 overflow-y-auto h-full">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Lightbulb className="w-6 h-6 text-amber-400" />
          <h1 className="text-xl font-bold text-gray-100">Recommendations</h1>
          {stats.total > 0 && (
            <span className="text-xs text-amber-400 bg-amber-900/30 px-2 py-0.5 rounded border border-amber-800">
              {stats.total} active
            </span>
          )}
        </div>
        <button onClick={fetch} className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {loading ? (
        <div className="text-center py-12 text-gray-500">Loading recommendations...</div>
      ) : recs.length === 0 ? (
        <div className="text-center py-16">
          <Lightbulb className="w-12 h-12 text-gray-700 mx-auto mb-3" />
          <p className="text-gray-500 text-sm">No active recommendations.</p>
          <p className="text-gray-600 text-xs mt-1">Findings from scans will generate actionable recommendations here.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {stats.by_module && Object.keys(stats.by_module).length > 0 && (
            <div className="flex gap-2 flex-wrap">
              {Object.entries(stats.by_module).map(([mod, count]) => {
                const Icon = MODULE_ICONS[mod] || Lightbulb
                return (
                  <div key={mod} className="flex items-center gap-1.5 bg-gray-800/50 border border-gray-700 rounded px-3 py-1.5 text-xs">
                    <Icon className="w-3.5 h-3.5 text-gray-400" />
                    <span className="text-gray-400 capitalize">{mod.replace('_', ' ')}</span>
                    <span className="text-amber-400 font-bold">{count}</span>
                  </div>
                )
              })}
            </div>
          )}

          {Object.entries(groupByModule(recs)).map(([module, items]) => {
            const Icon = MODULE_ICONS[module] || Lightbulb
            return (
              <div key={module}>
                <div className="flex items-center gap-2 mb-2">
                  <Icon className="w-4 h-4 text-gray-400" />
                  <h2 className="text-sm font-semibold text-gray-300 capitalize">{module.replace('_', ' ')}</h2>
                  <span className="text-xs text-gray-600">({items.length})</span>
                </div>
                <div className="space-y-1.5">
                  {items.map(rec => (
                    <div key={rec.id} className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 flex items-center gap-3 hover:border-gray-700 transition-colors group">
                      <div className={`w-2 h-2 rounded-full shrink-0 ${
                        rec.finding.severity === 'critical' ? 'bg-red-500' :
                        rec.finding.severity === 'high' ? 'bg-orange-500' :
                        rec.finding.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
                      }`} />
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium text-gray-200">{rec.label}</div>
                        <div className="text-xs text-gray-500">{rec.description}</div>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`text-[10px] font-mono px-1 py-0.5 rounded border ${SEV_COLORS[rec.finding.severity] || 'text-gray-500 bg-gray-800 border-gray-700'}`}>
                            {rec.finding.severity}
                          </span>
                          <span className="text-[10px] text-gray-600 truncate max-w-[200px]">{rec.finding.title}</span>
                          {rec.finding.cwe && (
                            <span className="text-[10px] text-gray-600 font-mono">{rec.finding.cwe}</span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        <button onClick={() => execute(rec)}
                          className="p-1.5 rounded text-amber-400 hover:text-amber-300 hover:bg-amber-900/30 transition-colors"
                          title="Execute">
                          <ChevronRight className="w-4 h-4" />
                        </button>
                        <button onClick={() => dismiss(rec.id)}
                          className="p-1.5 rounded text-gray-500 hover:text-gray-300 hover:bg-gray-800 transition-colors"
                          title="Dismiss">
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

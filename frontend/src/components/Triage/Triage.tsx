import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle, Filter, BarChart3, RefreshCw, ChevronRight, Zap, Bug, Repeat, Send } from 'lucide-react'
import { getGroupedFindings, getTriageStats, getRecentFindings, TriageGroup, TriageStats, RecentFinding } from '../../api/endpoints/triage'
import { useSessionStore } from '../../store/useSessionStore'

const SEV_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-900/30 border-red-800',
  high: 'text-orange-400 bg-orange-900/30 border-orange-800',
  medium: 'text-yellow-400 bg-yellow-900/30 border-yellow-800',
  low: 'text-blue-400 bg-blue-900/30 border-blue-800',
  info: 'text-gray-400 bg-gray-800/50 border-gray-700',
}

type View = 'grouped' | 'recent'

export function Triage() {
  const navigate = useNavigate()
  const { activeSessionId } = useSessionStore()
  const [view, setView] = useState<View>('grouped')
  const [groups, setGroups] = useState<TriageGroup[]>([])
  const [recent, setRecent] = useState<RecentFinding[]>([])
  const [stats, setStats] = useState<TriageStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [severityFilter, setSeverityFilter] = useState('all')

  const fetch = async () => {
    setLoading(true)
    try {
      const [g, s, r] = await Promise.all([
        getGroupedFindings(activeSessionId),
        getTriageStats(activeSessionId),
        getRecentFindings(activeSessionId),
      ])
      setGroups(g.groups); setStats(s); setRecent(r)
    } catch {} finally { setLoading(false) }
  }
  useEffect(() => { fetch() }, [activeSessionId])

  const filtered = severityFilter === 'all' ? groups : groups.filter(g => g.severity === severityFilter)

  const requestState = (g: TriageGroup) => ({
    url: g.url,
    method: g.method,
    headers: Object.entries(g.request_headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n'),
    body: g.request_body || '',
    host: g.host,
    path: g.endpoint,
    request_id: g.request_id,
    request_session_id: g.request_session_id,
  })

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6 overflow-y-auto h-full">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-6 h-6 text-purple-400" />
          <h1 className="text-xl font-bold text-gray-100">Smart Triage</h1>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex bg-gray-800 rounded-lg overflow-hidden">
            <button onClick={() => setView('grouped')} className={`px-3 py-1.5 text-xs font-medium transition-colors ${view === 'grouped' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-gray-200'}`}>Grouped</button>
            <button onClick={() => setView('recent')} className={`px-3 py-1.5 text-xs font-medium transition-colors ${view === 'recent' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-gray-200'}`}>Recent</button>
          </div>
          <select className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button onClick={fetch} className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors"><RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /></button>
        </div>
      </div>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
            <div key={sev} className={`${SEV_COLORS[sev]} rounded-lg px-4 py-3 border`}>
              <div className="text-xs uppercase tracking-wider opacity-70">{sev}</div>
              <div className="text-2xl font-bold mt-1">{(stats as any)[sev] || 0}</div>
            </div>
          ))}
          <div className="bg-gray-800/50 border border-gray-700 rounded-lg px-4 py-3">
            <div className="text-xs text-gray-400 uppercase tracking-wider">Total</div>
            <div className="text-2xl font-bold text-gray-100 mt-1">{stats.total_findings}</div>
          </div>
        </div>
      )}

      {loading ? (
        <div className="text-center py-12 text-gray-500">Loading...</div>
      ) : view === 'grouped' ? (
        filtered.length === 0 ? (
          <div className="text-center py-12 text-gray-500">No findings to triage.</div>
        ) : (
          <div className="space-y-2">
            {filtered.map(g => (
              <div key={g.key} className="bg-gray-900 border border-gray-800 rounded-lg px-5 py-3 hover:border-gray-700 transition-colors">
                <div className="flex items-center gap-3">
                  <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border shrink-0 ${SEV_COLORS[g.severity] || ''}`}>{g.severity}</span>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium text-gray-200 truncate">{g.title}</div>
                    <div className="text-xs text-gray-500 truncate">{g.endpoint} <span className="text-gray-600">×{g.count}</span></div>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <button onClick={() => navigate('/repeater', { state: requestState(g) })}
                      className="p-1.5 rounded text-blue-400 hover:text-blue-300 hover:bg-blue-900/30 transition-colors" title="Send to Repeater">
                      <Repeat size={14} />
                    </button>
                    <button onClick={() => navigate('/scanner/active', { state: requestState(g) })}
                      className="p-1.5 rounded text-amber-400 hover:text-amber-300 hover:bg-amber-900/30 transition-colors" title="Send to Scanner">
                      <Zap size={14} />
                    </button>
                    <button onClick={() => navigate('/fuzzer', { state: requestState(g) })}
                      className="p-1.5 rounded text-purple-400 hover:text-purple-300 hover:bg-purple-900/30 transition-colors" title="Send to Fuzzer">
                      <Bug size={14} />
                    </button>
                    <button onClick={() => navigate('/sequencer', { state: requestState(g) })}
                      className="p-1.5 rounded text-green-400 hover:text-green-300 hover:bg-green-900/30 transition-colors" title="Send to Sequencer">
                      <Send size={14} />
                    </button>
                  </div>
                </div>
                {g.evidence_preview && <p className="mt-2 text-xs text-gray-500 font-mono truncate">{g.evidence_preview}</p>}
              </div>
            ))}
          </div>
        )
      ) : (
        recent.length === 0 ? (
          <div className="text-center py-12 text-gray-500">No recent findings.</div>
        ) : (
          <div className="space-y-2">
            {recent.map(f => (
              <div key={f.id} className="bg-gray-900 border border-gray-800 rounded-lg px-5 py-3">
                <div className="flex items-center gap-3">
                  <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border shrink-0 ${SEV_COLORS[f.severity] || ''}`}>{f.severity}</span>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium text-gray-200 truncate">{f.title}</div>
                    <div className="text-xs text-gray-500 truncate"><span className="text-gray-600">{f.method}</span> {f.url}</div>
                  </div>
                  <span className="text-[10px] text-gray-500 shrink-0">{new Date(f.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            ))}
          </div>
        )
      )}
    </div>
  )
}

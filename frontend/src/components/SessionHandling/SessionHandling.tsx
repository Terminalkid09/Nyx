import { useState, useEffect } from 'react'
import { Users, Cookie, Play, Plus, Trash2, Share2, Shield, Edit3, X, Save, ChevronDown, ChevronRight } from 'lucide-react'
import {
  fetchSessionRules,
  createSessionRule,
  updateSessionRule,
  deleteSessionRule,
  updateMacroSteps,
  fetchCookies,
  addCookie,
  deleteCookie,
  runMacro,
} from '../../api/endpoints/sessionHandling'
import { apiClient } from '../../api/client'
import { useProxyStore } from '../../store/useProxyStore'
import { SessionHandlingRule, CookieEntry } from '../../types'

type Tab = 'rules' | 'cookies' | 'macros' | 'tokens'

interface MacroStep {
  method: string
  url: string
  headers?: Record<string, string>
  body?: string
  extract?: Record<string, string>
}

interface SessionToken {
  token_type: string
  value: string
  source: string
  request_id: string
  url: string
  method: string
}

export function SessionHandling() {
  const [activeTab, setActiveTab] = useState<Tab>('rules')
  const [rules, setRules] = useState<SessionHandlingRule[]>([])
  const [cookies, setCookies] = useState<CookieEntry[]>([])
  const [tokens, setTokens] = useState<SessionToken[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [domainFilter, setDomainFilter] = useState('')
  const [showAddRule, setShowAddRule] = useState(false)
  const [showAddCookie, setShowAddCookie] = useState(false)
  const [macroResults, setMacroResults] = useState<Record<string, unknown[]>>({})
  const [macroLoading, setMacroLoading] = useState<string | null>(null)
  const [showRecordMacro, setShowRecordMacro] = useState(false)
  const [selectedReqIds, setSelectedReqIds] = useState<string[]>([])
  const [expandedResults, setExpandedResults] = useState<Record<string, boolean>>({})

  // Macro Editor state
  const [editingMacro, setEditingMacro] = useState<SessionHandlingRule | null>(null)
  const [editSteps, setEditSteps] = useState<MacroStep[]>([])
  const [editStepIndex, setEditStepIndex] = useState<number>(0)
  const [editStepExpanded, setEditStepExpanded] = useState(false)

  const requests = useProxyStore((s) => s.requests)

  const [newRule, setNewRule] = useState<Partial<SessionHandlingRule>>({
    name: '', rule_type: 'cookie_jar', enabled: true, config: {}, order: 0,
  })
  const [newCookie, setNewCookie] = useState<Partial<CookieEntry>>({
    domain: '', name: '', value: '', path: '/', secure: false, http_only: false, same_site: 'Lax',
  })

  const loadData = (tab: Tab) => {
    setLoading(true); setError('')
    const promises: Promise<any>[] = []
    if (tab === 'rules' || tab === 'macros') promises.push(fetchSessionRules())
    if (tab === 'cookies') promises.push(fetchCookies(domainFilter || undefined))
    if (tab === 'tokens') promises.push(apiClient.get('/api/session/tokens'))
    Promise.all(promises)
      .then(([ruleData, cookieData, tokenData]) => {
        if (ruleData) setRules(ruleData)
        if (cookieData) setCookies(cookieData)
        if (tokenData) setTokens(tokenData.tokens || [])
        setLoading(false)
      })
      .catch((err: any) => { setError(err.response?.data?.detail || err.message); setLoading(false) })
  }

  useEffect(() => { loadData(activeTab) }, [activeTab])
  useEffect(() => {
    if (activeTab === 'cookies') fetchCookies(domainFilter || undefined).then(setCookies).catch(() => {})
  }, [domainFilter])

  const handleCreateRule = async () => {
    if (!newRule.name) return
    try {
      const created = await createSessionRule(newRule)
      setRules((prev) => [...prev, created])
      setShowAddRule(false)
      setNewRule({ name: '', rule_type: 'cookie_jar', enabled: true, config: {}, order: 0 })
    } catch (err: any) { setError(err.response?.data?.detail || err.message) }
  }

  const handleToggleRule = async (rule: SessionHandlingRule) => {
    try {
      const updated = await updateSessionRule(rule.id, { enabled: !rule.enabled })
      setRules((prev) => prev.map((r) => r.id === rule.id ? updated : r))
    } catch (err: any) { setError(err.response?.data?.detail || err.message) }
  }

  const handleDeleteRule = async (id: string) => {
    try {
      await deleteSessionRule(id)
      setRules((prev) => prev.filter((r) => r.id !== id))
    } catch (err: any) { setError(err.response?.data?.detail || err.message) }
  }

  const handleAddCookie = async () => {
    if (!newCookie.domain || !newCookie.name || !newCookie.value) return
    try {
      const created = await addCookie(newCookie as Partial<CookieEntry>)
      setCookies((prev) => [...prev, created])
      setShowAddCookie(false)
      setNewCookie({ domain: '', name: '', value: '', path: '/', secure: false, http_only: false, same_site: 'Lax' })
    } catch (err: any) { setError(err.response?.data?.detail || err.message) }
  }

  const handleDeleteCookie = async (id: string) => {
    try { await deleteCookie(id); setCookies((prev) => prev.filter((c) => c.id !== id)) }
    catch (err: any) { setError(err.response?.data?.detail || err.message) }
  }

  const handleRunMacro = async (rule: SessionHandlingRule) => {
    setMacroLoading(rule.id); setError('')
    try {
      const { results } = await runMacro(rule.id)
      setMacroResults((prev) => ({ ...prev, [rule.id]: results }))
    } catch (err: any) { setError(err.response?.data?.detail || err.message) }
    finally { setMacroLoading(null) }
  }

  const handleRecordMacro = async () => {
    if (selectedReqIds.length === 0) return
    try {
      const resp = await apiClient.post('/api/session/macros/from-requests', {
        session_id: '00000000-0000-0000-0000-000000000001',
        request_ids: selectedReqIds,
      })
      const steps = resp.data.steps
      const rule = await createSessionRule({
        name: `Macro from ${selectedReqIds.length} requests`,
        rule_type: 'macro',
        enabled: true,
        config: { requests: steps },
        order: 0,
      })
      setRules((prev) => [...prev, rule])
      setShowRecordMacro(false)
      setSelectedReqIds([])
    } catch (err: any) { setError(err.response?.data?.detail || err.message) }
  }

  const toggleRequestSelect = (id: string) => {
    setSelectedReqIds((prev) => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id])
  }

  // Macro Editor functions
  const openMacroEditor = (rule: SessionHandlingRule) => {
    const steps = (rule.config?.requests as MacroStep[]) || []
    setEditingMacro(rule)
    setEditSteps(steps.map(s => ({ ...s, headers: s.headers || {}, extract: s.extract || {} })))
    setEditStepIndex(0)
    setEditStepExpanded(false)
  }

  const closeMacroEditor = () => {
    setEditingMacro(null)
    setEditSteps([])
    setEditStepIndex(0)
  }

  const updateCurrentStep = (field: string, value: string | Record<string, string>) => {
    setEditSteps(prev => prev.map((s, i) => i === editStepIndex ? { ...s, [field]: value } : s))
  }

  const updateCurrentStepHeader = (key: string, value: string) => {
    setEditSteps(prev => prev.map((s, i) => {
      if (i !== editStepIndex) return s
      return { ...s, headers: { ...s.headers, [key]: value } }
    }))
  }

  const removeCurrentStepHeader = (key: string) => {
    setEditSteps(prev => prev.map((s, i) => {
      if (i !== editStepIndex) return s
      const h = { ...s.headers }
      delete h[key]
      return { ...s, headers: h }
    }))
  }

  const addCurrentStepHeader = () => {
    setEditSteps(prev => prev.map((s, i) => {
      if (i !== editStepIndex) return s
      return { ...s, headers: { ...s.headers, '': '' } }
    }))
  }

  const updateCurrentStepExtract = (key: string, value: string) => {
    setEditSteps(prev => prev.map((s, i) => {
      if (i !== editStepIndex) return s
      return { ...s, extract: { ...s.extract, [key]: value } }
    }))
  }

  const removeCurrentStepExtract = (key: string) => {
    setEditSteps(prev => prev.map((s, i) => {
      if (i !== editStepIndex) return s
      const e = { ...s.extract }
      delete e[key]
      return { ...s, extract: e }
    }))
  }

  const addCurrentStepExtract = () => {
    setEditSteps(prev => prev.map((s, i) => {
      if (i !== editStepIndex) return s
      return { ...s, extract: { ...s.extract, '': '' } }
    }))
  }

  const saveMacro = async () => {
    if (!editingMacro) return
    try {
      const cleanSteps = editSteps.map(s => {
        const step: MacroStep = { method: s.method, url: s.url }
        if (s.headers && Object.keys(s.headers).length > 0) {
          const clean = { ...s.headers }
          Object.keys(clean).forEach(k => { if (!k) delete clean[k] })
          if (Object.keys(clean).length > 0) step.headers = clean
        }
        if (s.body) step.body = s.body
        if (s.extract && Object.keys(s.extract).length > 0) {
          const clean = { ...s.extract }
          Object.keys(clean).forEach(k => { if (!k) delete clean[k] })
          if (Object.keys(clean).length > 0) step.extract = clean
        }
        return step
      })
      await updateMacroSteps(editingMacro.id, cleanSteps)
      const updated = await fetchSessionRules()
      setRules(updated)
      closeMacroEditor()
    } catch (err: any) { setError(err.response?.data?.detail || err.message) }
  }

  const addStepToMacro = () => {
    setEditSteps(prev => [...prev, { method: 'GET', url: '', headers: {}, body: '', extract: {} }])
    setEditStepIndex(editSteps.length)
  }

  const removeStepFromMacro = (idx: number) => {
    const steps = editSteps.filter((_, i) => i !== idx)
    setEditSteps(steps)
    if (editStepIndex >= steps.length && steps.length > 0) {
      setEditStepIndex(steps.length - 1)
    }
  }

  const moveStepInMacro = (from: number, to: number) => {
    const steps = [...editSteps]
    const [moved] = steps.splice(from, 1)
    steps.splice(to, 0, moved)
    setEditSteps(steps)
    setEditStepIndex(to)
  }

  const tabs: { id: Tab; label: string; icon: typeof Users }[] = [
    { id: 'rules', label: 'Rules', icon: Users },
    { id: 'cookies', label: 'Cookie Jar', icon: Cookie },
    { id: 'macros', label: 'Macros', icon: Play },
    { id: 'tokens', label: 'Session Tokens', icon: Shield },
  ]

  const RULE_TYPE_COLORS: Record<string, string> = {
    cookie_jar: 'text-blue-400 bg-blue-400/10',
    macro: 'text-purple-400 bg-purple-400/10',
    session_check: 'text-yellow-400 bg-yellow-400/10',
  }

  const methodColor = (m: string) => {
    switch (m.toUpperCase()) {
      case 'GET': return 'text-green-400'
      case 'POST': return 'text-blue-400'
      case 'PUT': return 'text-orange-400'
      case 'DELETE': return 'text-red-400'
      case 'PATCH': return 'text-purple-400'
      default: return 'text-gray-400'
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <Users size={16} /> <span>Session Handling</span>
      </div>

      {/* Editor Modal */}
      {editingMacro && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-900 border border-gray-700 rounded-lg w-[95vw] h-[90vh] flex flex-col">
            {/* Modal Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700 shrink-0">
              <div className="flex items-center gap-3">
                <Edit3 size={16} className="text-purple-400" />
                <span className="text-sm font-medium text-gray-200">Edit Macro: {editingMacro.name}</span>
                <span className="text-[10px] text-gray-500">{editSteps.length} steps</span>
              </div>
              <button onClick={closeMacroEditor} className="p-1 text-gray-500 hover:text-gray-300">
                <X size={16} />
              </button>
            </div>

            <div className="flex-1 flex min-h-0">
              {/* Left: Step List */}
              <div className="w-64 border-r border-gray-700 flex flex-col bg-gray-950/50">
                <div className="p-3 border-b border-gray-700 flex items-center justify-between">
                  <span className="text-xs font-medium text-gray-400">Steps</span>
                  <button onClick={addStepToMacro} className="text-purple-400 hover:text-purple-300">
                    <Plus size={14} />
                  </button>
                </div>
                <div className="flex-1 overflow-y-auto p-2 space-y-1">
                  {editSteps.map((step, idx) => (
                    <div
                      key={idx}
                      onClick={() => setEditStepIndex(idx)}
                      className={`flex items-center gap-2 p-2 rounded cursor-pointer text-xs transition-colors ${
                        idx === editStepIndex ? 'bg-purple-900/30 border border-purple-700/50' : 'bg-gray-800/50 border border-transparent hover:bg-gray-800'
                      }`}
                    >
                      <span className="text-gray-500 shrink-0 w-4">{idx + 1}</span>
                      <span className={`font-mono font-medium text-[10px] shrink-0 ${methodColor(step.method)}`}>{step.method}</span>
                      <span className="text-gray-300 truncate flex-1">{step.url ? (step.url.length > 30 ? step.url.slice(0, 30) + '…' : step.url) : '/'}</span>
                      <button onClick={(e) => { e.stopPropagation(); removeStepFromMacro(idx) }} className="text-gray-600 hover:text-red-400 shrink-0 opacity-0 hover:opacity-100">
                        <X size={12} />
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Right: Step Editor */}
              <div className="flex-1 flex flex-col min-h-0">
                {editSteps.length === 0 ? (
                  <div className="flex items-center justify-center h-full text-xs text-gray-500">Add steps to the macro using the + button</div>
                ) : (
                  <div className="flex-1 overflow-y-auto p-4 space-y-4">
                    {/* Request Line */}
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-[10px] font-medium text-gray-500 block mb-1">Method</label>
                        <select
                          value={editSteps[editStepIndex]?.method || 'GET'}
                          onChange={(e) => updateCurrentStep('method', e.target.value)}
                          className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-200"
                        >
                          {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => (
                            <option key={m} value={m}>{m}</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="text-[10px] font-medium text-gray-500 block mb-1">URL</label>
                        <input
                          value={editSteps[editStepIndex]?.url || ''}
                          onChange={(e) => updateCurrentStep('url', e.target.value)}
                          className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-200"
                          placeholder="https://example.com/api/login"
                        />
                      </div>
                    </div>

                    {/* Headers */}
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="text-[10px] font-medium text-gray-500">Headers</label>
                        <button onClick={addCurrentStepHeader} className="text-[10px] text-purple-400 hover:text-purple-300">+ Add Header</button>
                      </div>
                      <div className="space-y-1">
                        {Object.entries(editSteps[editStepIndex]?.headers || {}).map(([k, v], idx) => (
                          <div key={idx} className="flex items-center gap-2">
                            <input
                              value={k}
                              onChange={(e) => {
                                const h = { ...editSteps[editStepIndex].headers }
                                const keys = Object.keys(h)
                                const oldKey = keys[idx]
                                delete h[oldKey]
                                h[e.target.value] = v
                                updateCurrentStep('headers', h)
                              }}
                              className="w-40 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-[10px] font-mono text-gray-200"
                              placeholder="Header name"
                            />
                            <span className="text-gray-600">:</span>
                            <input
                              value={v}
                              onChange={(e) => updateCurrentStepHeader(k, e.target.value)}
                              className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-[10px] font-mono text-gray-200"
                              placeholder="Value (supports {{var}})"
                            />
                            <button onClick={() => removeCurrentStepHeader(k)} className="text-gray-600 hover:text-red-400">
                              <X size={12} />
                            </button>
                          </div>
                        ))}
                        {(!editSteps[editStepIndex]?.headers || Object.keys(editSteps[editStepIndex].headers).length === 0) && (
                          <div className="text-[10px] text-gray-600 py-1">No custom headers — click to add</div>
                        )}
                      </div>
                    </div>

                    {/* Body */}
                    <div>
                      <label className="text-[10px] font-medium text-gray-500 block mb-1">Body (optional)</label>
                      <textarea
                        value={editSteps[editStepIndex]?.body || ''}
                        onChange={(e) => updateCurrentStep('body', e.target.value)}
                        className="w-full h-24 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-200 resize-none"
                        placeholder='{"username":"admin","password":"{{password}}","csrf":"{{csrf_token}}"}'
                      />
                    </div>

                    {/* Extract Rules */}
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="text-[10px] font-medium text-gray-500">Extract Variables from Response</label>
                        <button onClick={addCurrentStepExtract} className="text-[10px] text-purple-400 hover:text-purple-300">+ Add Rule</button>
                      </div>
                      <div className="space-y-1">
                        {Object.entries(editSteps[editStepIndex]?.extract || {}).map(([k, v], idx) => (
                          <div key={idx} className="flex items-center gap-2">
                            <input
                              value={k}
                              onChange={(e) => {
                                const ex = { ...editSteps[editStepIndex].extract }
                                const keys = Object.keys(ex)
                                const oldKey = keys[idx]
                                delete ex[oldKey]
                                ex[e.target.value] = v
                                updateCurrentStep('extract', ex)
                              }}
                              className="w-36 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-[10px] font-mono text-gray-200"
                              placeholder="Variable name"
                            />
                            <span className="text-gray-600">=</span>
                            <input
                              value={v}
                              onChange={(e) => updateCurrentStepExtract(k, e.target.value)}
                              className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-[10px] font-mono text-gray-200"
                              placeholder='Regex: name="csrf" value="([^"]+)"'
                            />
                            <button onClick={() => removeCurrentStepExtract(k)} className="text-gray-600 hover:text-red-400">
                              <X size={12} />
                            </button>
                          </div>
                        ))}
                        {(!editSteps[editStepIndex]?.extract || Object.keys(editSteps[editStepIndex].extract).length === 0) && (
                          <div className="text-[10px] text-gray-600 py-1">No extraction rules — add regex patterns to capture variables from responses</div>
                        )}
                      </div>
                      <div className="mt-2 text-[10px] text-gray-600">
                        Use <code className="text-purple-400">{'{{variable_name}}'}</code> in URL, headers, and body to reference extracted values.
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-700 shrink-0">
              <span className="text-[10px] text-gray-600">
                {editSteps.length} step{editSteps.length !== 1 ? 's' : ''}
                {editSteps.some(s => s.extract && Object.keys(s.extract).length > 0) && (
                  <> — has variable extraction rules</>
                )}
              </span>
              <div className="flex items-center gap-2">
                <button onClick={closeMacroEditor} className="px-3 py-1.5 rounded text-xs text-gray-400 hover:text-gray-200 border border-gray-700">
                  Cancel
                </button>
                <button onClick={saveMacro} className="flex items-center gap-1.5 bg-purple-600 hover:bg-purple-700 px-3 py-1.5 rounded text-xs font-medium">
                  <Save size={12} /> Save Macro
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-gray-800">
        {tabs.map((tab) => {
          const Icon = tab.icon
          return (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1 px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
                activeTab === tab.id ? 'border-purple-500 text-purple-400' : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}>
              <Icon size={14} /> {tab.label}
            </button>
          )
        })}
      </div>
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>}

        {/* === RULES TAB === */}
        {activeTab === 'rules' && (
          <>
            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-500">{rules.length} rules</span>
              <button onClick={() => setShowAddRule(!showAddRule)}
                className="flex items-center gap-1 text-xs text-purple-400 hover:text-purple-300">
                <Plus size={14} /> Add Rule
              </button>
            </div>
            {showAddRule && (
              <div className="bg-gray-900 border border-gray-700 rounded p-3 space-y-2">
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Name</label>
                    <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                      value={newRule.name} onChange={e => setNewRule({ ...newRule, name: e.target.value })} placeholder="Rule name" />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Type</label>
                    <select className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                      value={newRule.rule_type} onChange={e => setNewRule({ ...newRule, rule_type: e.target.value as any })}>
                      <option value="cookie_jar">Cookie Jar</option>
                      <option value="macro">Macro</option>
                      <option value="session_check">Session Check</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Order</label>
                    <input type="number" className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                      value={newRule.order ?? 0} onChange={e => setNewRule({ ...newRule, order: Number(e.target.value) })} />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 block mb-1">URL Scope (optional, regex)</label>
                    <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
                      value={(newRule.config?.scope_url_pattern as string) || ''}
                      onChange={e => setNewRule({ ...newRule, config: { ...newRule.config, scope_url_pattern: e.target.value } })}
                      placeholder=".*\.example\.com/.*" />
                  </div>
                </div>
                <button onClick={handleCreateRule}
                  className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium" disabled={!newRule.name}>
                  Create
                </button>
              </div>
            )}
            {loading ? (
              <div className="text-xs text-gray-500">Loading...</div>
            ) : rules.length === 0 ? (
              <div className="text-xs text-gray-500 py-4 text-center">No rules defined.</div>
            ) : (
              <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-gray-800 text-gray-500">
                      <th className="text-left px-3 py-2 font-medium">Type</th>
                      <th className="text-left px-3 py-2 font-medium">Name</th>
                      <th className="text-left px-3 py-2 font-medium">Scope</th>
                      <th className="text-center px-3 py-2 font-medium">Enabled</th>
                      <th className="text-right px-3 py-2 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rules.map((rule) => {
                      const scope = (rule.config?.scope_url_pattern as string) || ''
                      return (
                        <tr key={rule.id} className="border-b border-gray-800 hover:bg-gray-800">
                          <td className="px-3 py-2">
                            <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${RULE_TYPE_COLORS[rule.rule_type] || 'text-gray-400'}`}>
                              {rule.rule_type}
                            </span>
                          </td>
                          <td className="px-3 py-2 text-gray-300">{rule.name}</td>
                          <td className="px-3 py-2">
                            {scope ? <span className="text-[10px] font-mono text-gray-500 truncate max-w-[120px] block">{scope}</span> : <span className="text-gray-600">—</span>}
                          </td>
                          <td className="px-3 py-2 text-center">
                            <button onClick={() => handleToggleRule(rule)}
                              className={`w-7 inline-block text-center rounded text-xs ${rule.enabled ? 'bg-green-600' : 'bg-gray-700'}`}>
                              {rule.enabled ? 'ON' : 'OFF'}
                            </button>
                          </td>
                          <td className="px-3 py-2 text-right">
                            <button onClick={() => handleDeleteRule(rule.id)} className="p-1 text-red-400 hover:text-red-300" title="Delete">
                              <Trash2 size={12} />
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}

        {/* === COOKIES TAB === */}
        {activeTab === 'cookies' && (
          <>
            <div className="flex items-center gap-2">
              <input className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                placeholder="Filter by domain..." value={domainFilter} onChange={e => setDomainFilter(e.target.value)} />
              <button onClick={() => setShowAddCookie(!showAddCookie)}
                className="flex items-center gap-1 text-xs text-purple-400 hover:text-purple-300">
                <Plus size={14} /> Add Cookie
              </button>
            </div>
            {showAddCookie && (
              <div className="bg-gray-900 border border-gray-700 rounded p-3 space-y-2">
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Domain</label>
                    <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                      value={newCookie.domain} onChange={e => setNewCookie({ ...newCookie, domain: e.target.value })} placeholder="example.com" />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Name</label>
                    <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                      value={newCookie.name} onChange={e => setNewCookie({ ...newCookie, name: e.target.value })} placeholder="sessionid" />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Value</label>
                    <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                      value={newCookie.value} onChange={e => setNewCookie({ ...newCookie, value: e.target.value })} placeholder="value" />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Path</label>
                    <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                      value={newCookie.path} onChange={e => setNewCookie({ ...newCookie, path: e.target.value })} />
                  </div>
                  <div className="flex items-end gap-4 pb-1">
                    <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer">
                      <input type="checkbox" checked={newCookie.secure || false}
                        onChange={e => setNewCookie({ ...newCookie, secure: e.target.checked })} className="accent-purple-500" /> Secure
                    </label>
                    <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer">
                      <input type="checkbox" checked={newCookie.http_only || false}
                        onChange={e => setNewCookie({ ...newCookie, http_only: e.target.checked })} className="accent-purple-500" /> HttpOnly
                    </label>
                  </div>
                </div>
                <button onClick={handleAddCookie}
                  className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium"
                  disabled={!newCookie.domain || !newCookie.name || !newCookie.value}>Add Cookie</button>
              </div>
            )}
            <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500">
                    <th className="text-left px-3 py-2 font-medium">Domain</th>
                    <th className="text-left px-3 py-2 font-medium">Name</th>
                    <th className="text-left px-3 py-2 font-medium">Value</th>
                    <th className="text-left px-3 py-2 font-medium">Path</th>
                    <th className="text-center px-3 py-2 font-medium">Secure</th>
                    <th className="text-center px-3 py-2 font-medium">HttpOnly</th>
                    <th className="text-right px-3 py-2 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {cookies.length === 0 ? (
                    <tr><td colSpan={7} className="px-3 py-4 text-center text-gray-500 text-xs">No cookies stored.</td></tr>
                  ) : (
                    cookies.map((cookie) => (
                      <tr key={cookie.id} className="border-b border-gray-800 hover:bg-gray-800">
                        <td className="px-3 py-2 text-gray-300">{cookie.domain}</td>
                        <td className="px-3 py-2 text-gray-300">{cookie.name}</td>
                        <td className="px-3 py-2 font-mono text-gray-400">{'•'.repeat(Math.min(String(cookie.value).length, 20))}</td>
                        <td className="px-3 py-2 text-gray-400">{cookie.path}</td>
                        <td className="px-3 py-2 text-center">
                          {cookie.secure ? <span className="text-green-400">✓</span> : <span className="text-gray-600">—</span>}
                        </td>
                        <td className="px-3 py-2 text-center">
                          {cookie.http_only ? <span className="text-green-400">✓</span> : <span className="text-gray-600">—</span>}
                        </td>
                        <td className="px-3 py-2 text-right">
                          <button onClick={() => handleDeleteCookie(cookie.id)} className="p-1 text-red-400 hover:text-red-300"><Trash2 size={12} /></button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* === MACROS TAB === */}
        {activeTab === 'macros' && (
          <>
            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-500">{rules.filter(r => r.rule_type === 'macro').length} macros</span>
              <button onClick={() => setShowRecordMacro(!showRecordMacro)}
                className="flex items-center gap-1 text-xs text-purple-400 hover:text-purple-300">
                <Share2 size={14} /> Record from Proxy
              </button>
            </div>

            {showRecordMacro && (
              <div className="bg-gray-900 border border-gray-700 rounded p-3 space-y-2">
                <div className="text-xs text-gray-400 mb-2">Select requests from proxy log to create a macro:</div>
                <div className="max-h-40 overflow-y-auto space-y-1">
                  {requests.slice(0, 50).map(r => (
                    <label key={r.id} className="flex items-center gap-2 cursor-pointer hover:bg-gray-800 rounded px-2 py-1">
                      <input type="checkbox" checked={selectedReqIds.includes(r.id)}
                        onChange={() => toggleRequestSelect(r.id)} className="accent-purple-500" />
                      <span className="text-[10px] text-gray-500 w-8">{r.method}</span>
                      <span className="text-xs text-gray-300 font-mono truncate">{r.path}</span>
                    </label>
                  ))}
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={handleRecordMacro} disabled={selectedReqIds.length === 0}
                    className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium disabled:opacity-50">
                    Create Macro ({selectedReqIds.length})
                  </button>
                  <span className="text-[10px] text-gray-600">Requests will be played in order</span>
                </div>
              </div>
            )}

            {loading ? (
              <div className="text-xs text-gray-500">Loading...</div>
            ) : rules.filter(r => r.rule_type === 'macro').length === 0 ? (
              <div className="text-xs text-gray-500 py-4 text-center">No macros. Create a macro rule or record from proxy.</div>
            ) : (
              <div className="space-y-2">
                {rules.filter(r => r.rule_type === 'macro').map(rule => {
                  const steps = (rule.config?.requests as any[]) || []
                  const isExpanded = expandedResults[rule.id]
                  return (
                    <div key={rule.id} className="bg-gray-900 border border-gray-800 rounded p-3">
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${rule.enabled ? 'bg-green-600' : 'bg-gray-700'}`}>
                          {rule.enabled ? 'ON' : 'OFF'}
                        </span>
                        <span className="text-xs text-gray-300 font-medium">{rule.name}</span>
                        <span className="text-[10px] text-gray-600">{steps.length} steps</span>
                        <button onClick={() => openMacroEditor(rule)}
                          className="flex items-center gap-1 text-gray-500 hover:text-purple-400 px-1.5 py-1 rounded text-[10px]">
                          <Edit3 size={11} /> Edit
                        </button>
                        <button onClick={() => handleRunMacro(rule)} disabled={macroLoading === rule.id}
                          className="ml-auto flex items-center gap-1 bg-purple-600 hover:bg-purple-700 px-2 py-1 rounded text-xs font-medium disabled:opacity-50">
                          <Play size={12} /> {macroLoading === rule.id ? 'Running...' : 'Run'}
                        </button>
                      </div>
                      {steps.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {steps.map((s: any, i: number) => (
                            <span key={i} className="text-[10px] px-1.5 py-0.5 bg-gray-800 rounded text-gray-400 font-mono flex items-center gap-1">
                              <span className={`font-medium ${s.method === 'GET' ? 'text-green-400' : s.method === 'POST' ? 'text-blue-400' : 'text-gray-400'}`}>{s.method}</span>
                              {s.url?.length > 35 ? s.url.slice(0, 35) + '…' : s.url || '?'}
                            </span>
                          ))}
                        </div>
                      )}
                      {macroResults[rule.id] && (
                        <div className="mt-2">
                          <button
                            className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-gray-300 mb-1"
                            onClick={() => setExpandedResults(prev => ({ ...prev, [rule.id]: !isExpanded }))}
                          >
                            {isExpanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
                            Results ({macroResults[rule.id].length} steps)
                          </button>
                          {isExpanded && (
                            <div className="bg-gray-950 border border-gray-800 rounded p-2 max-h-48 overflow-auto space-y-2">
                              {(macroResults[rule.id] as any[]).map((r: any, i: number) => (
                                <div key={i} className="text-xs border-b border-gray-800 pb-2 last:border-0">
                                  <div className="flex items-center gap-2 text-[10px] text-gray-500 mb-1">
                                    <span className="font-medium text-gray-400">Step {r.step}</span>
                                    <span className={methodColor(r.method)}>{r.method}</span>
                                    <span className="text-gray-600">{r.status}</span>
                                    <span className="text-gray-600">{r.size} bytes</span>
                                  </div>
                                  {r.body && (
                                    <pre className="text-[10px] text-gray-400 font-mono whitespace-pre-wrap line-clamp-3">{r.body}</pre>
                                  )}
                                  {r.error && <div className="text-red-400 text-[10px]">{r.error}</div>}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </>
        )}

        {/* === TOKENS TAB === */}
        {activeTab === 'tokens' && (
          <>
            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-500">{tokens.length} session tokens detected</span>
              <button onClick={() => loadData('tokens')} className="text-xs text-purple-400 hover:text-purple-300">Refresh</button>
            </div>
            {loading ? (
              <div className="text-xs text-gray-500">Scanning recent responses...</div>
            ) : tokens.length === 0 ? (
              <div className="text-xs text-gray-500 py-4 text-center">No session tokens detected. Send some requests through the proxy first.</div>
            ) : (
              <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-gray-800 text-gray-500">
                      <th className="text-left px-3 py-2 font-medium">Token Type</th>
                      <th className="text-left px-3 py-2 font-medium">Value</th>
                      <th className="text-left px-3 py-2 font-medium">Source</th>
                      <th className="text-left px-3 py-2 font-medium">URL</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tokens.map((t, i) => (
                      <tr key={i} className="border-b border-gray-800 hover:bg-gray-800">
                        <td className="px-3 py-2">
                          <span className="text-xs font-medium text-purple-400">{t.token_type}</span>
                        </td>
                        <td className="px-3 py-2 font-mono text-gray-300 truncate max-w-[150px]">{t.value}</td>
                        <td className="px-3 py-2 text-gray-500 text-[10px]">{t.source}</td>
                        <td className="px-3 py-2 font-mono text-gray-500 truncate max-w-[200px] text-[10px]">{t.url}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

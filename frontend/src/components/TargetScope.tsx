import { useState, useEffect, useCallback } from 'react'
import { apiClient } from '../api/client'

interface ScopeRule {
  id: string
  session_id: string | null
  enabled: boolean
  name: string
  rule_type: 'include' | 'exclude'
  pattern: string
  is_regex: boolean
  match_domain: boolean
  protocols: string[]
  order: number
  created_at: string
}

interface Suggestion {
  label: string
  pattern: string
  description: string
}

const ALL_PROTOCOLS = ['HTTP', 'HTTPS']

export function TargetScope() {
  const [rules, setRules] = useState<ScopeRule[]>([])
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editPattern, setEditPattern] = useState('')
  const [testUrl, setTestUrl] = useState('')
  const [testResult, setTestResult] = useState<{ in_scope: boolean; matched_rule: string | null; matched_by: string | null } | null>(null)
  const [error, setError] = useState('')
  const [regexValid, setRegexValid] = useState<Record<string, boolean | null>>({})
  const [regexError, setRegexError] = useState<Record<string, string>>({})
  const [suggestions, setSuggestions] = useState<Suggestion[]>([])

  useEffect(() => {
    loadRules()
    apiClient.get('/api/scope/suggestions').then(r => setSuggestions(r.data)).catch(() => {})
  }, [])

  const loadRules = async () => {
    try {
      const { data } = await apiClient.get('/api/scope/')
      setRules(data)
    } catch { setError('Failed to load rules') }
  }

  const validateRegex = useCallback(async (id: string, pattern: string) => {
    if (!pattern) {
      setRegexValid(prev => ({ ...prev, [id]: null }))
      setRegexError(prev => ({ ...prev, [id]: '' }))
      return
    }
    try {
      const { data } = await apiClient.post('/api/scope/validate-regex', { pattern })
      setRegexValid(prev => ({ ...prev, [id]: data.valid }))
      setRegexError(prev => ({ ...prev, [id]: data.error || '' }))
    } catch {
      setRegexValid(prev => ({ ...prev, [id]: false }))
    }
  }, [])

  const createRule = async (ruleType: 'include' | 'exclude') => {
    try {
      await apiClient.post('/api/scope/', {
        name: `New ${ruleType} rule`,
        rule_type: ruleType,
        pattern: '',
        is_regex: false,
        match_domain: false,
        protocols: ['HTTP', 'HTTPS'],
        order: rules.length,
        enabled: true,
      })
      await loadRules()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const updateRule = async (id: string, body: Record<string, any>) => {
    try {
      await apiClient.put(`/api/scope/${id}`, body)
      await loadRules()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const deleteRule = async (id: string) => {
    await apiClient.delete(`/api/scope/${id}`)
    setRules((prev) => prev.filter((r) => r.id !== id))
  }

  const toggleRule = async (id: string) => {
    await apiClient.patch(`/api/scope/${id}/toggle`)
    setRules((prev) => prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)))
  }

  const startEdit = (rule: ScopeRule) => {
    setEditingId(rule.id)
    setEditPattern(rule.pattern)
    if (rule.is_regex) validateRegex(rule.id, rule.pattern)
  }

  const saveEdit = async (rule: ScopeRule) => {
    if (editPattern !== rule.pattern) {
      await updateRule(rule.id, { pattern: editPattern })
    }
    setEditingId(null)
  }

  const toggleProtocol = async (rule: ScopeRule, proto: string) => {
    const next = rule.protocols.includes(proto)
      ? rule.protocols.filter((p) => p !== proto)
      : [...rule.protocols, proto]
    await updateRule(rule.id, { protocols: next })
  }

  const checkScope = async () => {
    if (!testUrl) return
    setError('')
    try {
      const { data } = await apiClient.post('/api/scope/check', { url: testUrl })
      setTestResult(data)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const applySuggestion = (pattern: string) => {
    if (!editingId) return
    setEditPattern(pattern)
    validateRegex(editingId, pattern)
  }

  const includes = rules.filter((r) => r.rule_type === 'include')
  const excludes = rules.filter((r) => r.rule_type === 'exclude')

  const renderTable = (items: ScopeRule[]) => (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-gray-500 border-b border-gray-800">
          <th className="text-left py-2 px-2 w-16">On</th>
          <th className="text-left py-2 px-2">Name</th>
          <th className="text-left py-2 px-2">Pattern</th>
          <th className="text-center py-2 px-2 w-12">Rx</th>
          <th className="text-center py-2 px-2 w-12">Dom</th>
          <th className="text-left py-2 px-2 w-28">Protocols</th>
          <th className="text-center py-2 px-2 w-12">Ord</th>
          <th className="text-right py-2 px-2 w-20">Actions</th>
        </tr>
      </thead>
      <tbody>
        {items.map((rule) => (
          <tr key={rule.id} className={`border-b border-gray-800/50 hover:bg-gray-800/30 ${!rule.enabled ? 'opacity-50' : ''}`}>
            <td className="py-1.5 px-2">
              <button
                onClick={() => toggleRule(rule.id)}
                className={`w-8 text-center rounded text-[10px] ${rule.enabled ? 'bg-green-700 text-green-200' : 'bg-gray-700 text-gray-400'}`}
              >
                {rule.enabled ? 'ON' : 'OFF'}
              </button>
            </td>
            <td className="py-1.5 px-2 text-gray-200">{rule.name}</td>
            <td className="py-1.5 px-2 font-mono relative">
              {editingId === rule.id ? (
                <div className="flex flex-col gap-1">
                  <input
                    className="w-full bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200 font-mono"
                    value={editPattern}
                    onChange={(e) => { setEditPattern(e.target.value); if (rule.is_regex) validateRegex(rule.id, e.target.value) }}
                    onBlur={() => saveEdit(rule)}
                    onKeyDown={(e) => e.key === 'Enter' && saveEdit(rule)}
                    autoFocus
                  />
                  {rule.is_regex && regexValid[rule.id] !== null && (
                    <span className={`text-[10px] ${regexValid[rule.id] ? 'text-green-400' : 'text-red-400'}`}>
                      {regexValid[rule.id] ? 'Valid regex' : regexError[rule.id] || 'Invalid regex'}
                    </span>
                  )}
                  {rule.is_regex && suggestions.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1">
                      {suggestions.map((s, i) => (
                        <button key={i} onClick={() => applySuggestion(s.pattern)}
                          className="text-[9px] bg-gray-700 hover:bg-gray-600 text-gray-300 px-1.5 py-0.5 rounded">
                          {s.label}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <span className="cursor-pointer hover:text-purple-400" onClick={() => startEdit(rule)}>
                  {rule.pattern ? (
                    <span className="flex items-center gap-1">
                      {rule.pattern}
                      {rule.is_regex && regexValid[rule.id] === false && <span className="text-red-400 text-[9px]">⚠</span>}
                    </span>
                  ) : (
                    <span className="text-gray-600 italic">click to edit</span>
                  )}
                </span>
              )}
            </td>
            <td className="py-1.5 px-2 text-center">
              <button
                onClick={() => updateRule(rule.id, { is_regex: !rule.is_regex })}
                className={`text-[10px] px-1.5 py-0.5 rounded ${rule.is_regex ? 'bg-purple-700 text-purple-200' : 'bg-gray-700 text-gray-400'}`}
              >
                {rule.is_regex ? 'ON' : 'OFF'}
              </button>
            </td>
            <td className="py-1.5 px-2 text-center">
              <button
                onClick={() => updateRule(rule.id, { match_domain: !rule.match_domain })}
                className={`text-[10px] px-1.5 py-0.5 rounded ${rule.match_domain ? 'bg-cyan-700 text-cyan-200' : 'bg-gray-700 text-gray-400'}`}
              >
                {rule.match_domain ? 'ON' : 'OFF'}
              </button>
            </td>
            <td className="py-1.5 px-2">
              <div className="flex gap-1">
                {ALL_PROTOCOLS.map((p) => (
                  <button
                    key={p}
                    onClick={() => toggleProtocol(rule, p)}
                    className={`text-[10px] px-1.5 py-0.5 rounded ${
                      rule.protocols.includes(p) ? 'bg-blue-700 text-blue-200' : 'bg-gray-700 text-gray-400'
                    }`}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </td>
            <td className="py-1.5 px-2 text-center text-gray-400">{rule.order}</td>
            <td className="py-1.5 px-2 text-right">
              <button onClick={() => deleteRule(rule.id)} className="text-red-400 hover:text-red-300 text-[10px]">Delete</button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300">
        Target Scope Rules
      </div>
      <div className="flex-1 p-4 space-y-4 overflow-auto">
        {error && (
          <div className="bg-red-900/50 border border-red-800 rounded px-3 py-2 text-xs text-red-300">{error}</div>
        )}

        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-gray-400 font-medium">Include Rules ({includes.length})</span>
            <button
              className="bg-green-700 hover:bg-green-600 px-3 py-1 rounded text-xs font-medium"
              onClick={() => createRule('include')}
            >
              Add Include Rule
            </button>
          </div>
          <div className="border border-gray-800 rounded overflow-hidden">
            {includes.length > 0 ? renderTable(includes) : (
              <div className="p-3 text-xs text-gray-500">No include rules. All URLs will be in scope.</div>
            )}
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-gray-400 font-medium">Exclude Rules ({excludes.length})</span>
            <button
              className="bg-red-700 hover:bg-red-600 px-3 py-1 rounded text-xs font-medium"
              onClick={() => createRule('exclude')}
            >
              Add Exclude Rule
            </button>
          </div>
          <div className="border border-gray-800 rounded overflow-hidden">
            {excludes.length > 0 ? renderTable(excludes) : (
              <div className="p-3 text-xs text-gray-500">No exclude rules.</div>
            )}
          </div>
        </div>

        <div className="border border-gray-800 rounded p-3">
          <div className="text-xs text-gray-400 font-medium mb-2">URL Tester</div>
          <div className="flex gap-2">
            <input
              className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
              placeholder="https://example.com/some/path"
              value={testUrl}
              onChange={(e) => { setTestUrl(e.target.value); setTestResult(null) }}
              onKeyDown={(e) => e.key === 'Enter' && checkScope()}
            />
            <button
              className="bg-purple-600 hover:bg-purple-700 px-4 py-1 rounded text-xs font-medium disabled:opacity-50"
              onClick={checkScope}
              disabled={!testUrl}
            >
              Check
            </button>
          </div>
          {testResult && (
            <div className={`mt-2 text-xs px-3 py-2 rounded ${testResult.in_scope ? 'bg-green-900/50 text-green-300 border border-green-800' : 'bg-red-900/50 text-red-300 border border-red-800'}`}>
              <strong>{testResult.in_scope ? 'In Scope' : 'Out of Scope'}</strong>
              {testResult.matched_rule && (
                <span className="ml-2">
                  — matched by <span className="font-mono">{testResult.matched_rule}</span> ({testResult.matched_by})
                </span>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

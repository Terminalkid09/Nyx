import { useState, useEffect, useCallback } from 'react'
import { Plus, Trash2, Save, X, TestTube, GripVertical, ArrowUp, ArrowDown } from 'lucide-react'
import { apiClient } from '../../api/client'

interface Rule {
  id: string
  session_id: string | null
  enabled: boolean
  name: string
  scope: string
  match_type: string
  match_pattern: string
  is_regex: boolean
  replacement: string
  order: number
}

interface TestResult {
  replaced_text: string
  match_count: number
}

const EMPTY_RULE: Partial<Rule> = {
  enabled: true,
  name: '',
  scope: 'request',
  match_type: 'string',
  match_pattern: '',
  is_regex: false,
  replacement: '',
  order: 0,
}

const SCOPES = ['request', 'response', 'request_header', 'response_header', 'request_body', 'response_body']
const MATCH_TYPES = ['string', 'regex']

export function RuleManager() {
  const [rules, setRules] = useState<Rule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showAddForm, setShowAddForm] = useState(false)
  const [newRule, setNewRule] = useState<Partial<Rule>>({ ...EMPTY_RULE })
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editData, setEditData] = useState<Partial<Rule>>({})
  const [testRuleId, setTestRuleId] = useState<string | null>(null)
  const [testInput, setTestInput] = useState('')
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [testLoading, setTestLoading] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)

  const fetchRules = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const { data } = await apiClient.get<Rule[]>('/api/match-replace/')
      setRules(data)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchRules() }, [fetchRules])

  const handleCreate = async () => {
    if (!newRule.name || !newRule.match_pattern) return
    try {
      const { data } = await apiClient.post<Rule>('/api/match-replace/', newRule)
      setRules((prev) => [...prev, data])
      setShowAddForm(false)
      setNewRule({ ...EMPTY_RULE })
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const startEdit = (rule: Rule) => {
    setEditingId(rule.id)
    setEditData({ ...rule })
  }

  const cancelEdit = () => {
    setEditingId(null)
    setEditData({})
  }

  const saveEdit = async () => {
    if (!editingId) return
    try {
      const { data } = await apiClient.put<Rule>(`/api/match-replace/${editingId}`, editData)
      setRules((prev) => prev.map((r) => (r.id === editingId ? data : r)))
      setEditingId(null)
      setEditData({})
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const toggleEnabled = async (rule: Rule) => {
    try {
      const { data } = await apiClient.patch<Rule>(`/api/match-replace/${rule.id}/toggle`)
      setRules((prev) => prev.map((r) => (r.id === rule.id ? data : r)))
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleDelete = async (id: string) => {
    try {
      await apiClient.delete(`/api/match-replace/${id}`)
      setRules((prev) => prev.filter((r) => r.id !== id))
      setConfirmDelete(null)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const moveRule = async (index: number, direction: -1 | 1) => {
    const newRules = [...rules]
    const target = index + direction
    if (target < 0 || target >= newRules.length) return
    ;[newRules[index], newRules[target]] = [newRules[target], newRules[index]]
    const reorder = newRules.map((r, i) => ({ id: r.id, order: i }))
    try {
      const { data } = await apiClient.patch<Rule[]>('/api/match-replace/reorder', reorder)
      const updated = newRules.map((r) => data.find((u) => u.id === r.id) || r)
      setRules(updated)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
      fetchRules()
    }
  }

  const openTest = (rule: Rule) => {
    setTestRuleId(rule.id)
    setTestInput(rule.match_pattern)
    setTestResult(null)
  }

  const runTest = async () => {
    if (!testRuleId) return
    setTestLoading(true)
    setTestResult(null)
    try {
      const { data } = await apiClient.put<TestResult>(`/api/match-replace/${testRuleId}/test`, {
        input_text: testInput,
      })
      setTestResult(data)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setTestLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <span>Match & Replace Rules</span>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-3">
        {error && (
          <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>
        )}

        <div className="flex items-center justify-between">
          <span className="text-xs text-gray-500">
            {rules.length} rule{rules.length !== 1 ? 's' : ''}
          </span>
          <button
            onClick={() => setShowAddForm(!showAddForm)}
            className="flex items-center gap-1 text-xs text-purple-400 hover:text-purple-300"
          >
            <Plus size={14} /> Add Rule
          </button>
        </div>

        {showAddForm && (
          <div className="bg-gray-900 border border-gray-700 rounded p-3 space-y-2">
            <div className="grid grid-cols-2 gap-x-3 gap-y-2">
              <div>
                <label className="text-[10px] text-gray-500 block mb-0.5">Name</label>
                <input
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                  value={newRule.name || ''}
                  onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                  placeholder="Rule name"
                />
              </div>
              <div>
                <label className="text-[10px] text-gray-500 block mb-0.5">Scope</label>
                <select
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                  value={newRule.scope}
                  onChange={(e) => setNewRule({ ...newRule, scope: e.target.value })}
                >
                  {SCOPES.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-gray-500 block mb-0.5">Match Type</label>
                <select
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                  value={newRule.match_type}
                  onChange={(e) => setNewRule({ ...newRule, match_type: e.target.value, is_regex: e.target.value === 'regex' })}
                >
                  {MATCH_TYPES.map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-gray-500 block mb-0.5">Match Pattern</label>
                <input
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
                  value={newRule.match_pattern || ''}
                  onChange={(e) => setNewRule({ ...newRule, match_pattern: e.target.value })}
                  placeholder="pattern"
                />
              </div>
              <div>
                <label className="text-[10px] text-gray-500 block mb-0.5">Replacement</label>
                <input
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
                  value={newRule.replacement || ''}
                  onChange={(e) => setNewRule({ ...newRule, replacement: e.target.value })}
                  placeholder="replacement"
                />
              </div>
              <div>
                <label className="text-[10px] text-gray-500 block mb-0.5">Order</label>
                <input
                  type="number"
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                  value={newRule.order ?? 0}
                  onChange={(e) => setNewRule({ ...newRule, order: Number(e.target.value) })}
                />
              </div>
            </div>
            <div className="flex items-center gap-2 pt-1">
              <button
                onClick={handleCreate}
                disabled={!newRule.name || !newRule.match_pattern}
                className="bg-purple-600 hover:bg-purple-700 disabled:opacity-50 px-3 py-1 rounded text-xs font-medium"
              >
                Create
              </button>
              <button
                onClick={() => setShowAddForm(false)}
                className="text-gray-400 hover:text-gray-300 text-xs px-2"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500">
                <th className="w-6 px-1 py-2" />
                <th className="w-10 px-1 py-2 text-left font-medium">On</th>
                <th className="px-2 py-2 text-left font-medium">Name</th>
                <th className="px-2 py-2 text-left font-medium">Scope</th>
                <th className="px-2 py-2 text-left font-medium">Type</th>
                <th className="px-2 py-2 text-left font-medium">Match</th>
                <th className="px-2 py-2 text-left font-medium">Replace</th>
                <th className="w-10 px-1 py-2 text-center font-medium">Order</th>
                <th className="w-28 px-1 py-2 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={9} className="px-3 py-8 text-center text-gray-500 text-xs">Loading...</td>
                </tr>
              ) : rules.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-3 py-8 text-center text-gray-500 text-xs">
                    No rules yet. Rules automatically rewrite requests/responses in real-time.
                  </td>
                </tr>
              ) : (
                rules.map((rule, index) => (
                  <tr
                    key={rule.id}
                    className={`border-b border-gray-800 hover:bg-gray-800/50 ${
                      !rule.enabled ? 'opacity-50' : ''
                    }`}
                  >
                    <td className="px-1 py-1.5 align-middle">
                      <div className="flex flex-col items-center gap-0">
                        <button
                          onClick={() => moveRule(index, -1)}
                          disabled={index === 0}
                          className="text-gray-600 hover:text-gray-300 disabled:opacity-30 p-0 leading-none"
                        >
                          <ArrowUp size={10} />
                        </button>
                        <button
                          onClick={() => moveRule(index, 1)}
                          disabled={index === rules.length - 1}
                          className="text-gray-600 hover:text-gray-300 disabled:opacity-30 p-0 leading-none"
                        >
                          <ArrowDown size={10} />
                        </button>
                      </div>
                    </td>

                    {editingId === rule.id ? (
                      <>
                        <td className="px-1 py-1.5">
                          <button
                            onClick={() => setEditData({ ...editData, enabled: !editData.enabled })}
                            className={`w-7 text-center rounded text-[10px] font-medium ${
                              editData.enabled ? 'bg-green-600' : 'bg-gray-700'
                            }`}
                          >
                            {editData.enabled ? 'ON' : 'OFF'}
                          </button>
                        </td>
                        <td className="px-2 py-1.5">
                          <input
                            className="w-20 bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200"
                            value={editData.name || ''}
                            onChange={(e) => setEditData({ ...editData, name: e.target.value })}
                          />
                        </td>
                        <td className="px-2 py-1.5">
                          <select
                            className="bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200"
                            value={editData.scope || 'request'}
                            onChange={(e) => setEditData({ ...editData, scope: e.target.value })}
                          >
                            {SCOPES.map((s) => (
                              <option key={s} value={s}>{s}</option>
                            ))}
                          </select>
                        </td>
                        <td className="px-2 py-1.5">
                          <select
                            className="bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200"
                            value={editData.match_type || 'string'}
                            onChange={(e) => setEditData({
                              ...editData,
                              match_type: e.target.value,
                              is_regex: e.target.value === 'regex',
                            })}
                          >
                            {MATCH_TYPES.map((t) => (
                              <option key={t} value={t}>{t}</option>
                            ))}
                          </select>
                        </td>
                        <td className="px-2 py-1.5">
                          <input
                            className="w-24 bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200 font-mono"
                            value={editData.match_pattern || ''}
                            onChange={(e) => setEditData({ ...editData, match_pattern: e.target.value })}
                          />
                        </td>
                        <td className="px-2 py-1.5">
                          <input
                            className="w-20 bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200 font-mono"
                            value={editData.replacement || ''}
                            onChange={(e) => setEditData({ ...editData, replacement: e.target.value })}
                          />
                        </td>
                        <td className="px-1 py-1.5 text-center">
                          <input
                            type="number"
                            className="w-10 bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200 text-center"
                            value={editData.order ?? 0}
                            onChange={(e) => setEditData({ ...editData, order: Number(e.target.value) })}
                          />
                        </td>
                        <td className="px-1 py-1.5 text-right">
                          <div className="flex items-center justify-end gap-0.5">
                            <button
                              onClick={saveEdit}
                              className="p-1 text-green-400 hover:text-green-300"
                              title="Save"
                            >
                              <Save size={12} />
                            </button>
                            <button
                              onClick={cancelEdit}
                              className="p-1 text-gray-400 hover:text-gray-300"
                              title="Cancel"
                            >
                              <X size={12} />
                            </button>
                          </div>
                        </td>
                      </>
                    ) : (
                      <>
                        <td className="px-1 py-1.5">
                          <button
                            onClick={() => toggleEnabled(rule)}
                            className={`w-7 text-center rounded text-[10px] font-medium ${
                              rule.enabled ? 'bg-green-600' : 'bg-gray-700'
                            }`}
                          >
                            {rule.enabled ? 'ON' : 'OFF'}
                          </button>
                        </td>
                        <td className="px-2 py-1.5 text-gray-200 font-medium truncate max-w-[120px]">{rule.name}</td>
                        <td className="px-2 py-1.5 text-gray-400">{rule.scope}</td>
                        <td className="px-2 py-1.5 text-gray-400">{rule.match_type}</td>
                        <td className="px-2 py-1.5 text-gray-400 font-mono truncate max-w-[140px]">{rule.match_pattern}</td>
                        <td className="px-2 py-1.5 text-gray-400 font-mono truncate max-w-[120px]">{rule.replacement}</td>
                        <td className="px-1 py-1.5 text-center text-gray-400">{rule.order}</td>
                        <td className="px-1 py-1.5 text-right">
                          <div className="flex items-center justify-end gap-0.5">
                            <button
                              onClick={() => openTest(rule)}
                              className="p-1 text-cyan-400 hover:text-cyan-300"
                              title="Test"
                            >
                              <TestTube size={12} />
                            </button>
                            <button
                              onClick={() => startEdit(rule)}
                              className="p-1 text-gray-400 hover:text-gray-300"
                              title="Edit"
                            >
                              <Save size={12} />
                            </button>
                            {confirmDelete === rule.id ? (
                              <>
                                <button
                                  onClick={() => handleDelete(rule.id)}
                                  className="p-1 text-red-400 hover:text-red-300 font-medium"
                                  title="Confirm delete"
                                >
                                  <Trash2 size={12} />
                                </button>
                                <button
                                  onClick={() => setConfirmDelete(null)}
                                  className="p-1 text-gray-400 hover:text-gray-300"
                                  title="Cancel"
                                >
                                  <X size={12} />
                                </button>
                              </>
                            ) : (
                              <button
                                onClick={() => setConfirmDelete(rule.id)}
                                className="p-1 text-red-400 hover:text-red-300"
                                title="Delete"
                              >
                                <Trash2 size={12} />
                              </button>
                            )}
                          </div>
                        </td>
                      </>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {testRuleId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-900 border border-gray-700 rounded-lg shadow-xl w-full max-w-xl mx-4">
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
              <span className="text-sm font-medium text-gray-200">Test Rule</span>
              <button
                onClick={() => { setTestRuleId(null); setTestResult(null) }}
                className="text-gray-400 hover:text-gray-200"
              >
                <X size={16} />
              </button>
            </div>
            <div className="p-4 space-y-3">
              <div>
                <label className="text-xs text-gray-500 block mb-1">Input Text</label>
                <textarea
                  className="w-full h-28 bg-gray-950 border border-gray-800 rounded p-2 text-xs font-mono text-gray-200 resize-none"
                  value={testInput}
                  onChange={(e) => setTestInput(e.target.value)}
                  placeholder="Enter text to test the rule against..."
                />
              </div>
              <button
                onClick={runTest}
                disabled={testLoading || !testInput}
                className="bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 px-3 py-1.5 rounded text-xs font-medium"
              >
                {testLoading ? 'Testing...' : 'Run Test'}
              </button>
              {testResult && (
                <div className="space-y-2">
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-gray-500">Result</span>
                      <span className="text-xs text-gray-400">
                        Matches: <span className="text-cyan-400 font-medium">{testResult.match_count}</span>
                      </span>
                    </div>
                    <pre className="w-full max-h-48 overflow-auto bg-gray-950 border border-gray-800 rounded p-2 text-xs font-mono text-gray-200 whitespace-pre-wrap break-all">
                      {testResult.replaced_text}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

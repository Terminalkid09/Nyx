import { useState, useEffect } from 'react'
import { apiClient } from '../../api/client'

interface CustomCheck {
  id: string
  enabled: boolean
  name: string
  description: string | null
  severity: string
  match_type: string
  match_pattern: string
  is_regex: boolean
  payload: string | null
  created_at: string
}

const MATCH_TYPES = [
  { value: 'response_body', label: 'Response Body' },
  { value: 'url', label: 'URL' },
  { value: 'response_headers', label: 'Response Headers' },
]

const SEVERITIES = [
  { value: 'info', label: 'Info', color: 'text-blue-400' },
  { value: 'low', label: 'Low', color: 'text-green-400' },
  { value: 'medium', label: 'Medium', color: 'text-yellow-400' },
  { value: 'high', label: 'High', color: 'text-orange-400' },
  { value: 'critical', label: 'Critical', color: 'text-red-400' },
]

const emptyForm = () => ({
  name: '',
  description: '',
  severity: 'medium',
  match_type: 'response_body',
  match_pattern: '',
  is_regex: true,
  payload: '',
})

export function CustomChecks() {
  const [checks, setChecks] = useState<CustomCheck[]>([])
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState(emptyForm())
  const [editingId, setEditingId] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [testUrl, setTestUrl] = useState('')
  const [testBody, setTestBody] = useState('')
  const [testResults, setTestResults] = useState<any[] | null>(null)

  useEffect(() => { loadChecks() }, [])

  const loadChecks = async () => {
    try {
      const { data } = await apiClient.get('/api/scanner/custom/')
      setChecks(data)
    } catch { setError('Failed to load custom checks') }
  }

  const save = async () => {
    setError('')
    try {
      if (editingId) {
        await apiClient.put(`/api/scanner/custom/${editingId}`, form)
      } else {
        await apiClient.post('/api/scanner/custom/', form)
      }
      setShowForm(false)
      setEditingId(null)
      setForm(emptyForm())
      await loadChecks()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const edit = (check: CustomCheck) => {
    setForm({
      name: check.name,
      description: check.description || '',
      severity: check.severity,
      match_type: check.match_type,
      match_pattern: check.match_pattern,
      is_regex: check.is_regex,
      payload: check.payload || '',
    })
    setEditingId(check.id)
    setShowForm(true)
  }

  const remove = async (id: string) => {
    await apiClient.delete(`/api/scanner/custom/${id}`)
    setChecks(prev => prev.filter(c => c.id !== id))
  }

  const runTest = async () => {
    setError('')
    try {
      const { data } = await apiClient.post('/api/scanner/custom/run', {
        url: testUrl,
        response_body: testBody,
        response_headers: {},
      })
      setTestResults(data)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center justify-between">
        <span>Custom Scanner Checks</span>
        <button onClick={() => { setShowForm(!showForm); if (!showForm) { setEditingId(null); setForm(emptyForm()) } }}
          className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium">
          {showForm ? 'Cancel' : 'New Check'}
        </button>
      </div>
      <div className="flex-1 p-4 space-y-4 overflow-auto">
        {error && <div className="bg-red-900/50 border border-red-800 rounded px-3 py-2 text-xs text-red-300">{error}</div>}

        {showForm && (
          <div className="bg-gray-900/80 border border-gray-700/50 rounded-lg p-4 space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">Name</label>
                <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                  value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
              </div>
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">Severity</label>
                <select className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                  value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })}>
                  {SEVERITIES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
                </select>
              </div>
            </div>
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Description</label>
              <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">Match Type</label>
                <select className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                  value={form.match_type} onChange={e => setForm({ ...form, match_type: e.target.value })}>
                  {MATCH_TYPES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                </select>
              </div>
              <div className="flex items-end gap-2">
                <label className="flex items-center gap-2 text-xs text-gray-400 pb-1">
                  <input type="checkbox" checked={form.is_regex}
                    onChange={e => setForm({ ...form, is_regex: e.target.checked })}
                    className="accent-purple-500" />
                  Regex
                </label>
              </div>
            </div>
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Match Pattern</label>
              <textarea className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
                rows={2} value={form.match_pattern}
                onChange={e => setForm({ ...form, match_pattern: e.target.value })} />
            </div>
            <div>
              <label className="text-[10px] text-gray-500 block mb-1">Payload (optional — sent in request)</label>
              <textarea className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
                rows={2} value={form.payload}
                onChange={e => setForm({ ...form, payload: e.target.value })} />
            </div>
            <button onClick={save} disabled={!form.name || !form.match_pattern}
              className="bg-purple-600 hover:bg-purple-700 px-4 py-1.5 rounded text-xs font-medium disabled:opacity-50">
              {editingId ? 'Update' : 'Create'} Check
            </button>
          </div>
        )}

        <div className="space-y-1">
          {checks.length === 0 && !showForm && (
            <div className="text-xs text-gray-500 text-center py-8">No custom checks defined.</div>
          )}
          {checks.map(check => (
            <div key={check.id} className="bg-gray-900/80 border border-gray-800 rounded-lg p-3 flex items-center justify-between">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-bold ${SEVERITIES.find(s => s.value === check.severity)?.color || 'text-gray-400'}`}>
                    {check.severity.toUpperCase()}
                  </span>
                  <span className="text-xs text-gray-200 font-medium">{check.name}</span>
                  {!check.enabled && <span className="text-[10px] text-gray-600">(disabled)</span>}
                </div>
                {check.description && <div className="text-[10px] text-gray-500 mt-0.5 truncate">{check.description}</div>}
                <div className="text-[9px] text-gray-600 mt-0.5 font-mono truncate">{check.match_pattern}</div>
              </div>
              <div className="flex items-center gap-2 ml-3 shrink-0">
                <span className="text-[10px] text-gray-600">{check.match_type}</span>
                <button onClick={() => edit(check)} className="text-[10px] text-purple-400 hover:text-purple-300">Edit</button>
                <button onClick={() => remove(check.id)} className="text-[10px] text-red-400 hover:text-red-300">Del</button>
              </div>
            </div>
          ))}
        </div>

        <details className="border border-gray-800 rounded-lg">
          <summary className="text-xs text-gray-400 font-medium p-3 cursor-pointer hover:bg-gray-800/50">Test Custom Checks</summary>
          <div className="p-3 space-y-2">
            <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
              placeholder="URL" value={testUrl} onChange={e => setTestUrl(e.target.value)} />
            <textarea className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
              rows={3} placeholder="Response body to test against" value={testBody}
              onChange={e => setTestBody(e.target.value)} />
            <button onClick={runTest} disabled={!testBody}
              className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium disabled:opacity-50">
              Run Test
            </button>
            {testResults && (
              <div className="space-y-1 mt-2">
                {testResults.filter(r => r.triggered).length === 0 && (
                  <div className="text-xs text-green-400">No checks triggered.</div>
                )}
                {testResults.filter(r => r.triggered).map(r => (
                  <div key={r.check_id} className="text-xs text-orange-400 bg-orange-900/20 border border-orange-800/50 rounded px-2 py-1">
                    <strong>{r.check_name}</strong> ({r.severity})
                    {r.evidence && <div className="text-gray-400 mt-0.5 font-mono text-[10px]">{r.evidence}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </details>
      </div>
    </div>
  )
}

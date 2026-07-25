import { useState, useEffect } from 'react'
import { PauseCircle, PlayCircle, Forward, XCircle, Plus, Trash2 } from 'lucide-react'
import {
  fetchInterceptorStatus,
  fetchInterceptorRules,
  createInterceptorRule,
  updateInterceptorRule,
  deleteInterceptorRule,
  toggleInterceptor,
  fetchPausedItems,
  forwardItem,
  dropItem,
} from '../../api/endpoints/interceptor'
import { InterceptorRule, InterceptedItem } from '../../types'

export function Interceptor() {
  const [enabled, setEnabled] = useState(false)
  const [pausedItems, setPausedItems] = useState<InterceptedItem[]>([])
  const [rules, setRules] = useState<InterceptorRule[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedItem, setSelectedItem] = useState<InterceptedItem | null>(null)
  const [editHeaders, setEditHeaders] = useState('')
  const [editBody, setEditBody] = useState('')
  const [showAddRule, setShowAddRule] = useState(false)
  const [newRule, setNewRule] = useState<Partial<InterceptorRule>>({
    name: '',
    scope: 'request',
    match_type: 'header',
    match_pattern: '',
    is_regex: false,
    enabled: true,
    order: 0,
    intercept_on_match: true,
  })
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null)
  const [editRule, setEditRule] = useState<Partial<InterceptorRule>>({})
  const [error, setError] = useState('')

  const loadData = () => {
    setLoading(true)
    setError('')
    Promise.all([
      fetchInterceptorStatus(),
      fetchPausedItems(),
      fetchInterceptorRules(),
    ]).then(([status, items, fetchedRules]) => {
      setEnabled(status.enabled)
      setPausedItems(items)
      setRules(fetchedRules)
      setLoading(false)
    }).catch((err: any) => {
      setError(err.response?.data?.detail || err.message)
      setLoading(false)
    })
  }

  useEffect(() => { loadData() }, [])

  const handleToggleInterceptor = async () => {
    try {
      const { enabled: newState } = await toggleInterceptor()
      setEnabled(newState)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleForward = async (item: InterceptedItem) => {
    try {
      const mods: any = {}
      if (item.modified_method) mods.method = item.modified_method
      if (item.modified_url) mods.url = item.modified_url
      if (editHeaders && selectedItem?.id === item.id) {
        try { mods.headers = JSON.parse(editHeaders) } catch {}
      }
      if (editBody && selectedItem?.id === item.id) {
        mods.body = editBody
      }
      await forwardItem(item.id, mods)
      setPausedItems((prev) => prev.filter((i) => i.id !== item.id))
      if (selectedItem?.id === item.id) setSelectedItem(null)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleDrop = async (item: InterceptedItem) => {
    try {
      await dropItem(item.id)
      setPausedItems((prev) => prev.filter((i) => i.id !== item.id))
      if (selectedItem?.id === item.id) setSelectedItem(null)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const selectItem = (item: InterceptedItem) => {
    setSelectedItem(item)
    if (item.modified_headers) setEditHeaders(JSON.stringify(item.modified_headers, null, 2))
    else setEditHeaders('')
    setEditBody(item.modified_body || '')
  }

  const handleAddRule = async () => {
    if (!newRule.name || !newRule.match_pattern) return
    try {
      const created = await createInterceptorRule(newRule)
      setRules((prev) => [...prev, created])
      setShowAddRule(false)
      setNewRule({ name: '', scope: 'request', match_type: 'header', match_pattern: '', is_regex: false, enabled: true, order: 0, intercept_on_match: true })
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const startEditRule = (rule: InterceptorRule) => {
    setEditingRuleId(rule.id)
    setEditRule({ ...rule })
  }

  const saveEditRule = async () => {
    if (!editingRuleId || !editRule.name) return
    try {
      const updated = await updateInterceptorRule(editingRuleId, editRule)
      setRules((prev) => prev.map((r) => r.id === editingRuleId ? updated : r))
      setEditingRuleId(null)
      setEditRule({})
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const cancelEditRule = () => {
    setEditingRuleId(null)
    setEditRule({})
  }

  const handleDeleteRule = async (id: string) => {
    try {
      await deleteInterceptorRule(id)
      setRules((prev) => prev.filter((r) => r.id !== id))
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const toggleRuleEnabled = async (rule: InterceptorRule) => {
    try {
      const updated = await updateInterceptorRule(rule.id, { enabled: !rule.enabled })
      setRules((prev) => prev.map((r) => r.id === rule.id ? updated : r))
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <PauseCircle size={16} />
        <span>Interceptor</span>
      </div>
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>}

        <div className="flex items-center gap-3 bg-gray-900 border border-gray-800 rounded p-3">
          <span className="text-xs text-gray-300">Intercept</span>
          <button
            onClick={handleToggleInterceptor}
            className={`relative w-10 h-5 rounded-full transition-colors overflow-hidden ${
              enabled ? 'bg-green-600' : 'bg-gray-700'
            }`}
          >
            <span
              className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
                enabled ? 'translate-x-5' : 'translate-x-0'
              }`}
            />
          </button>
          <span className={`text-xs font-medium ${enabled ? 'text-green-400' : 'text-gray-500'}`}>
            {enabled ? 'On' : 'Off'}
          </span>
          <span className="text-xs text-gray-500 ml-auto">
            {pausedItems.length} paused
          </span>
        </div>

        <div>
          <div className="text-xs font-medium text-gray-400 mb-1 flex items-center gap-2">
            <PlayCircle size={14} />
            Paused Items
          </div>
          {loading ? (
            <div className="text-xs text-gray-500">Loading...</div>
          ) : pausedItems.length === 0 ? (
            <div className="text-xs text-gray-500">No paused items.</div>
          ) : (
            <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500">
                    <th className="text-left px-3 py-2 font-medium">Direction</th>
                    <th className="text-left px-3 py-2 font-medium">Method</th>
                    <th className="text-left px-3 py-2 font-medium">URL</th>
                    <th className="text-left px-3 py-2 font-medium">Status</th>
                    <th className="text-right px-3 py-2 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {pausedItems.map((item) => (
                    <tr
                      key={item.id}
                      className={`border-b border-gray-800 cursor-pointer hover:bg-gray-800 ${
                        selectedItem?.id === item.id ? 'bg-gray-800' : ''
                      }`}
                      onClick={() => selectItem(item)}
                    >
                      <td className="px-3 py-2">
                        <span className={`text-xs font-medium ${
                          item.direction === 'request' ? 'text-blue-400' : 'text-green-400'
                        }`}>
                          {item.direction}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-purple-400">{item.modified_method || '…'}</td>
                      <td className="px-3 py-2 text-gray-300 truncate max-w-xs">{item.modified_url || '…'}</td>
                      <td className="px-3 py-2 text-gray-400">{item.status}</td>
                      <td className="px-3 py-2 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={(e) => { e.stopPropagation(); handleForward(item) }}
                            className="p-1 text-green-400 hover:text-green-300"
                            title="Forward"
                          >
                            <Forward size={14} />
                          </button>
                          <button
                            onClick={(e) => { e.stopPropagation(); handleDrop(item) }}
                            className="p-1 text-red-400 hover:text-red-300"
                            title="Drop"
                          >
                            <XCircle size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {selectedItem && (
          <div className="bg-gray-900 border border-gray-800 rounded p-3 space-y-2">
            <div className="text-xs font-medium text-gray-400">Modify Item</div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">Headers (JSON)</label>
              <textarea
                className="w-full h-24 bg-gray-950 border border-gray-800 rounded p-2 text-xs font-mono text-gray-300 resize-none"
                value={editHeaders}
                onChange={(e) => setEditHeaders(e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">Body</label>
              <textarea
                className="w-full h-24 bg-gray-950 border border-gray-800 rounded p-2 text-xs font-mono text-gray-300 resize-none"
                value={editBody}
                onChange={(e) => setEditBody(e.target.value)}
              />
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => handleForward(selectedItem)}
                className="bg-green-600 hover:bg-green-700 px-3 py-1 rounded text-xs font-medium flex items-center gap-1"
              >
                <Forward size={12} /> Forward
              </button>
              <button
                onClick={() => handleDrop(selectedItem)}
                className="bg-red-600 hover:bg-red-700 px-3 py-1 rounded text-xs font-medium flex items-center gap-1"
              >
                <XCircle size={12} /> Drop
              </button>
            </div>
          </div>
        )}

        <div>
          <div className="flex items-center justify-between mb-1">
            <div className="text-xs font-medium text-gray-400 flex items-center gap-2">
              <PauseCircle size={14} />
              Interceptor Rules
            </div>
            <button
              onClick={() => setShowAddRule(!showAddRule)}
              className="flex items-center gap-1 text-xs text-purple-400 hover:text-purple-300"
            >
              <Plus size={14} /> Add Rule
            </button>
          </div>

          {showAddRule && (
            <div className="bg-gray-900 border border-gray-700 rounded p-3 mb-2 space-y-2">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-xs text-gray-500 block mb-1">Name</label>
                  <input
                    className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                    value={newRule.name}
                    onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                    placeholder="Rule name"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-500 block mb-1">Scope</label>
                  <select
                    className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                    value={newRule.scope}
                    onChange={(e) => setNewRule({ ...newRule, scope: e.target.value as 'request' | 'response' | 'both' })}
                  >
                    <option value="request">Request</option>
                    <option value="response">Response</option>
                    <option value="both">Both</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-gray-500 block mb-1">Match Type</label>
                  <input
                    className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                    value={newRule.match_type || ''}
                    onChange={(e) => setNewRule({ ...newRule, match_type: e.target.value })}
                    placeholder="header, body, url..."
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-500 block mb-1">Match Pattern</label>
                  <input
                    className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                    value={newRule.match_pattern || ''}
                    onChange={(e) => setNewRule({ ...newRule, match_pattern: e.target.value })}
                    placeholder="pattern"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-500 block mb-1">Order</label>
                  <input
                    type="number"
                    className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                    value={newRule.order ?? 0}
                    onChange={(e) => setNewRule({ ...newRule, order: Number(e.target.value) })}
                  />
                </div>
                <div className="flex items-end gap-4 pb-1">
                  <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={newRule.is_regex || false}
                      onChange={(e) => setNewRule({ ...newRule, is_regex: e.target.checked })}
                      className="accent-purple-500"
                    />
                    Regex
                  </label>
                  <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={newRule.intercept_on_match ?? true}
                      onChange={(e) => setNewRule({ ...newRule, intercept_on_match: e.target.checked })}
                      className="accent-purple-500"
                    />
                    Intercept
                  </label>
                </div>
              </div>
              <button
                onClick={handleAddRule}
                className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium"
                disabled={!newRule.name || !newRule.match_pattern}
              >
                Create Rule
              </button>
            </div>
          )}

          <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500">
                  <th className="text-left px-3 py-2 font-medium">Enabled</th>
                  <th className="text-left px-3 py-2 font-medium">Name</th>
                  <th className="text-left px-3 py-2 font-medium">Scope</th>
                  <th className="text-left px-3 py-2 font-medium">Match Type</th>
                  <th className="text-left px-3 py-2 font-medium">Match Pattern</th>
                  <th className="text-center px-3 py-2 font-medium">Regex</th>
                  <th className="text-center px-3 py-2 font-medium">Order</th>
                  <th className="text-right px-3 py-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.length === 0 && !showAddRule && (
                  <tr>
                    <td colSpan={8} className="px-3 py-4 text-center text-gray-500 text-xs">
                      No rules defined.
                    </td>
                  </tr>
                )}
                {rules.map((rule) => (
                  <tr key={rule.id} className="border-b border-gray-800 hover:bg-gray-800">
                    {editingRuleId === rule.id ? (
                      <>
                        <td className="px-3 py-2">
                          <button
                            onClick={() => setEditRule({ ...editRule, enabled: !editRule.enabled })}
                            className={`w-7 text-center rounded text-xs ${
                              editRule.enabled ? 'bg-green-600' : 'bg-gray-700'
                            }`}
                          >
                            {editRule.enabled ? 'ON' : 'OFF'}
                          </button>
                        </td>
                        <td className="px-3 py-2">
                          <input
                            className="w-24 bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200"
                            value={editRule.name || ''}
                            onChange={(e) => setEditRule({ ...editRule, name: e.target.value })}
                          />
                        </td>
                        <td className="px-3 py-2">
                          <select
                            className="bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200"
                            value={editRule.scope || 'request'}
                            onChange={(e) => setEditRule({ ...editRule, scope: e.target.value as any })}
                          >
                            <option value="request">request</option>
                            <option value="response">response</option>
                            <option value="both">both</option>
                          </select>
                        </td>
                        <td className="px-3 py-2">
                          <input
                            className="w-20 bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200"
                            value={editRule.match_type || ''}
                            onChange={(e) => setEditRule({ ...editRule, match_type: e.target.value })}
                          />
                        </td>
                        <td className="px-3 py-2">
                          <input
                            className="w-24 bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200"
                            value={editRule.match_pattern || ''}
                            onChange={(e) => setEditRule({ ...editRule, match_pattern: e.target.value })}
                          />
                        </td>
                        <td className="px-3 py-2 text-center">
                          <input
                            type="checkbox"
                            checked={editRule.is_regex || false}
                            onChange={(e) => setEditRule({ ...editRule, is_regex: e.target.checked })}
                            className="accent-purple-500"
                          />
                        </td>
                        <td className="px-3 py-2 text-center">
                          <input
                            type="number"
                            className="w-12 bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200 text-center"
                            value={editRule.order ?? 0}
                            onChange={(e) => setEditRule({ ...editRule, order: Number(e.target.value) })}
                          />
                        </td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex items-center justify-end gap-1">
                            <button onClick={saveEditRule} className="text-green-400 hover:text-green-300 text-xs px-1">Save</button>
                            <button onClick={cancelEditRule} className="text-gray-500 hover:text-gray-400 text-xs px-1">Cancel</button>
                          </div>
                        </td>
                      </>
                    ) : (
                      <>
                        <td className="px-3 py-2">
                          <button
                            onClick={() => toggleRuleEnabled(rule)}
                            className={`w-7 text-center rounded text-xs ${
                              rule.enabled ? 'bg-green-600' : 'bg-gray-700'
                            }`}
                          >
                            {rule.enabled ? 'ON' : 'OFF'}
                          </button>
                        </td>
                        <td className="px-3 py-2 text-gray-300">{rule.name}</td>
                        <td className="px-3 py-2 text-gray-400">{rule.scope}</td>
                        <td className="px-3 py-2 text-gray-400">{rule.match_type || '—'}</td>
                        <td className="px-3 py-2 text-gray-400 font-mono truncate max-w-[120px]">{rule.match_pattern || '—'}</td>
                        <td className="px-3 py-2 text-center text-gray-400">{rule.is_regex ? '✓' : '—'}</td>
                        <td className="px-3 py-2 text-center text-gray-400">{rule.order}</td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex items-center justify-end gap-1">
                            <button
                              onClick={() => startEditRule(rule)}
                              className="p-1 text-gray-400 hover:text-gray-300"
                              title="Edit"
                            >
                              <Forward size={12} />
                            </button>
                            <button
                              onClick={() => handleDeleteRule(rule.id)}
                              className="p-1 text-red-400 hover:text-red-300"
                              title="Delete"
                            >
                              <Trash2 size={12} />
                            </button>
                          </div>
                        </td>
                      </>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}

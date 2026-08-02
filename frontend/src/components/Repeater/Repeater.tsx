import { useState, useEffect, useCallback, useMemo } from 'react'
import { useSearchParams, useLocation } from 'react-router-dom'
import { Plus, X, History } from 'lucide-react'
import { RequestEditor } from './RequestEditor'
import { sendRequest, fetchTabs, createTab, closeTab, fetchTabHistory } from '../../api/endpoints/repeater'

interface TabData {
  id: string
  name: string
  method: string
  scheme: string
  url: string
  headers: string
  body: string
  response: any
  history: any[]
  loading: boolean
  error: string | null
}

let tabCounter = 1

function freshTab(url?: string, method?: string, headers?: string, body?: string, name?: string): TabData {
  let scheme = 'https'
  let cleanUrl = url || ''
  if (cleanUrl) {
    const m = cleanUrl.match(/^(https?):\/\//)
    if (m) { scheme = m[1]; cleanUrl = cleanUrl.slice(m[0].length) }
  }
  return {
    id: crypto.randomUUID?.() || Math.random().toString(36).slice(2, 10),
    name: name || `Request ${tabCounter++}`,
    method: method || 'GET',
    scheme,
    url: cleanUrl,
    headers: headers || '',
    body: body || '',
    response: null,
    history: [],
    loading: false,
    error: null,
  }
}

export function Repeater() {
  const [searchParams] = useSearchParams()
  const location = useLocation()
  const initialTabId = searchParams.get('tab')
  const queryUrl = searchParams.get('url')
  const navState = (location.state || {}) as Record<string, any>
  const prefillUrl = navState.url || queryUrl || ''
  const prefillMethod = navState.method || ''
  const prefillHeaders = navState.headers || ''
  const prefillBody = navState.body || ''
  const [tabs, setTabs] = useState<TabData[]>([freshTab(prefillUrl, prefillMethod, prefillHeaders, prefillBody)])
  const [activeId, setActiveId] = useState<string>(tabs[0].id)
  const [editingTabId, setEditingTabId] = useState<string | null>(null)
  const [editName, setEditName] = useState('')
  const [historyOpen, setHistoryOpen] = useState<string | null>(null)

  useEffect(() => {
    fetchTabs().then((backendTabs) => {
      if (!backendTabs || backendTabs.length === 0) return
      Promise.all(
        backendTabs.map((t: any) =>
          fetchTabHistory(t.id).then((history) => ({ tab: t, history })).catch(() => ({ tab: t, history: [] })),
        ),
      ).then((results) => {
        const mapped = results.map(({ tab, history }) => {
          const haveData = history.length > 0 ? history[history.length - 1] : null
          let url = haveData?.url || ''
          let scheme = 'https'
          const m = typeof url === 'string' && url.match(/^(https?):\/\//)
          if (m) { scheme = m[1]; url = url.slice(m[0].length) }
          return {
            id: tab.id,
            name: tab.name || 'Request',
            method: haveData?.method || 'GET',
            scheme,
            url,
            headers: haveData?.headers ? Object.entries(haveData.headers).map(([k, v]) => `${k}: ${v}`).join('\n') : '',
            body: haveData?.body || '',
            response: haveData?.response_status ? { status: haveData.response_status, headers: haveData.response_headers, body: haveData.response_body, time_ms: haveData.time_ms } : null,
            history,
            loading: false,
            error: null,
          } as TabData
        })
        // If this tab was opened with prefill data (e.g. "Send to Repeater"
        // from Triage/Fuzzer/Scanner), keep it instead of letting the backend
        // tabs overwrite the user's pending request.
        const hasPrefill = !!(prefillUrl || prefillMethod || prefillHeaders || prefillBody)
        const nextTabs = hasPrefill ? [...tabs, ...mapped.filter(t => t.id !== tabs[0].id)] : mapped
        setTabs(nextTabs)
        const targetIdx = initialTabId ? mapped.findIndex(t => t.id === initialTabId) : -1
        setActiveId(targetIdx >= 0 ? mapped[targetIdx].id : (hasPrefill ? tabs[0].id : mapped[0].id))
      })
    }).catch(() => {})
  }, [initialTabId])

  const activeTab = useMemo(
    () => tabs.find((t) => t.id === activeId) || tabs[0],
    [tabs, activeId]
  )

  const updateTab = useCallback((id: string, patch: Partial<TabData>) => {
    setTabs((prev) => prev.map((t) => (t.id === id ? { ...t, ...patch } : t)))
  }, [])

  const handleAddTab = useCallback(() => {
    const tab = freshTab()
    setTabs((prev) => [...prev, tab])
    setActiveId(tab.id)
  }, [])

  const handleCloseTab = useCallback((id: string) => {
    setTabs((prev) => {
      const next = prev.filter((t) => t.id !== id)
      if (next.length === 0) {
        const t = freshTab()
        return [t]
      }
      if (id === activeId) {
        const idx = prev.findIndex((t) => t.id === id)
        const newActive = next[Math.min(idx, next.length - 1)]
        setActiveId(newActive.id)
      }
      return next
    })
    closeTab(id).catch(() => {})
  }, [activeId])

  const handleSend = useCallback(async () => {
    if (!activeTab || !activeTab.url) return
    const fullUrl = `${activeTab.scheme}://${activeTab.url}`
    updateTab(activeTab.id, { loading: true, error: null })
    try {
      const hdrs: Record<string, string> = {}
      activeTab.headers.split('\n').forEach((line) => {
        const idx = line.indexOf(':')
        if (idx > 0) {
          const k = line.slice(0, idx).trim()
          const v = line.slice(idx + 1).trim()
          if (k) hdrs[k] = v
        }
      })
      const result = await sendRequest(activeTab.method, fullUrl, hdrs, activeTab.body || undefined)
      const entry = {
        method: activeTab.method,
        url: fullUrl,
        headers: hdrs,
        body: activeTab.body,
        response_status: result.status,
        response_headers: result.headers,
        response_body: result.body,
        time_ms: result.time_ms,
        timestamp: new Date().toISOString(),
      }
      updateTab(activeTab.id, { response: result, loading: false, history: [...activeTab.history, entry] })
    } catch (err: any) {
      updateTab(activeTab.id, { loading: false, error: err.message || 'Request failed' })
    }
  }, [activeTab, updateTab])

  const handleLoadHistory = useCallback(async (tabId: string) => {
    try {
      const entries = await fetchTabHistory(tabId)
      updateTab(tabId, { history: entries })
    } catch {}
  }, [updateTab])

  const handleSelectHistory = useCallback((entry: any) => {
    if (!activeTab) return
    let url = entry.url || ''
    let scheme = 'https'
    const m = url.match(/^(https?):\/\//)
    if (m) {
      scheme = m[1]
      url = url.slice(m[0].length)
    }
    updateTab(activeTab.id, {
      method: entry.method,
      scheme,
      url,
      headers: Object.entries(entry.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n'),
      body: entry.body || '',
      response: entry.response_status
        ? { status: entry.response_status, headers: entry.response_headers, body: entry.response_body, time_ms: entry.time_ms }
        : null,
    })
    setHistoryOpen(null)
  }, [activeTab, updateTab])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault()
        handleSend()
      }
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'N' || e.key === 'n')) {
        e.preventDefault()
        handleAddTab()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [handleSend, handleAddTab])

  const handleDoubleClickTab = (tab: TabData) => {
    setEditingTabId(tab.id)
    setEditName(tab.name)
  }

  const handleRenameSubmit = (id: string) => {
    if (editName.trim()) {
      updateTab(id, { name: editName.trim() })
    }
    setEditingTabId(null)
  }

  const handleMethodChange = useCallback((val: string) => updateTab(activeId, { method: val }), [activeId])
  const handleSchemeChange = useCallback((val: string) => updateTab(activeId, { scheme: val }), [activeId])
  const handleUrlChange = useCallback((val: string) => updateTab(activeId, { url: val }), [activeId])
  const handleHeadersChange = useCallback((val: string) => updateTab(activeId, { headers: val }), [activeId])
  const handleBodyChange = useCallback((val: string) => updateTab(activeId, { body: val }), [activeId])

  return (
    <div className="flex flex-col h-full bg-gray-900">
      <div className="flex items-center border-b border-gray-800 bg-gray-800/50 overflow-x-auto">
        <div className="flex-1 flex">
          {tabs.map((tab) => (
            <div
              key={tab.id}
              className={`group flex items-center gap-1 px-3 py-1.5 text-xs border-r border-gray-800 cursor-pointer select-none shrink-0 transition-colors ${
                tab.id === activeId ? 'bg-gray-800 text-gray-200' : 'text-gray-400 hover:text-gray-300 hover:bg-gray-800/50'
              }`}
              onClick={() => {
                setActiveId(tab.id)
                setHistoryOpen(null)
              }}
              onDoubleClick={() => handleDoubleClickTab(tab)}
            >
              {editingTabId === tab.id ? (
                <input
                  className="w-20 bg-gray-700 text-gray-200 text-xs px-1 py-0 rounded outline-none border border-purple-500"
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  onBlur={() => handleRenameSubmit(tab.id)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleRenameSubmit(tab.id)
                    if (e.key === 'Escape') setEditingTabId(null)
                  }}
                  autoFocus
                  onClick={(e) => e.stopPropagation()}
                />
              ) : (
                <span className="max-w-24 truncate flex items-center gap-1">
                  {tab.loading && (
                    <span className="w-2 h-2 rounded-full bg-yellow-400 animate-pulse shrink-0" />
                  )}
                  {tab.name}
                </span>
              )}
              <button
                className="opacity-0 group-hover:opacity-100 transition-opacity hover:text-red-400"
                onClick={(e) => {
                  e.stopPropagation()
                  handleCloseTab(tab.id)
                }}
              >
                <X className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
        <div className="flex items-center gap-1 px-2 shrink-0">
          <button
            className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-gray-200 transition-colors"
            onClick={() => {
              if (activeTab) {
                setHistoryOpen(historyOpen === activeTab.id ? null : activeTab.id)
                handleLoadHistory(activeTab.id)
              }
            }}
            title="Request history"
          >
            <History className="w-3.5 h-3.5" />
          </button>
          <button
            className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-gray-200 transition-colors"
            onClick={handleAddTab}
            title="New tab (Ctrl+Shift+N)"
          >
            <Plus className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
      {historyOpen && activeTab && (
        <div className="border-b border-gray-800 bg-gray-800/50 max-h-32 overflow-y-auto">
          {activeTab.history.length === 0 ? (
            <div className="text-xs text-gray-500 p-2">No history for this tab</div>
          ) : (
            activeTab.history.map((entry: any, i: number) => (
              <div
                key={i}
                className="flex items-center gap-2 px-3 py-1 text-xs cursor-pointer hover:bg-gray-700 text-gray-300"
                onClick={() => handleSelectHistory(entry)}
              >
                <span className="text-gray-500 shrink-0">{entry.timestamp?.slice(11, 19) || ''}</span>
                <span className="font-medium text-purple-400 shrink-0 w-12">{entry.method}</span>
                <span className="truncate text-gray-400">{entry.url}</span>
                <span className="text-gray-500 shrink-0 ml-auto">
                  {entry.response_status || '—'}
                </span>
              </div>
            ))
          )}
        </div>
      )}
      <RequestEditor
        method={activeTab.method}
        scheme={activeTab.scheme}
        url={activeTab.url}
        headers={activeTab.headers}
        body={activeTab.body}
        response={activeTab.response}
        loading={activeTab.loading}
        error={activeTab.error}
        onMethodChange={handleMethodChange}
        onSchemeChange={handleSchemeChange}
        onUrlChange={handleUrlChange}
        onHeadersChange={handleHeadersChange}
        onBodyChange={handleBodyChange}
        onSend={handleSend}
      />
    </div>
  )
}

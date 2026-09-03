import { useState, useRef, useEffect } from 'react'
import { Plus, ChevronDown, Check, Trash2, Loader2, Database, Eraser } from 'lucide-react'
import { useSessionStore, DEFAULT_SESSION_ID } from '../../store/useSessionStore'
import { apiClient } from '../../api/client'
import { useProxyStore } from '../../store/useProxyStore'
import { useFindingsStore } from '../../store/useFindingsStore'

export function SessionSwitcher() {
  const { sessions, activeSessionId, loading, fetchSessions, createSession, deleteSession, activateSession } =
    useSessionStore()

  const [open, setOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  const [newName, setNewName] = useState('')
  const [switching, setSwitching] = useState(false)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [resettingId, setResettingId] = useState<string | null>(null)
  const ref = useRef<HTMLDivElement>(null)

  const activeSession = sessions.find((s) => s.id === activeSessionId)
  const displayName = activeSession?.name ?? 'Default Session'

  useEffect(() => {
    fetchSessions()
  }, [fetchSessions])

  // Close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const handleActivate = async (id: string) => {
    if (id === activeSessionId) { setOpen(false); return }
    setSwitching(true)
    try {
      await activateSession(id)
    } finally {
      setSwitching(false)
      setOpen(false)
    }
  }

  const handleCreate = async () => {
    const name = newName.trim()
    if (!name) return
    setCreating(true)
    try {
      const sess = await createSession(name)
      await activateSession(sess.id)
      setNewName('')
    } finally {
      setCreating(false)
      setOpen(false)
    }
  }

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation()
    if (id === DEFAULT_SESSION_ID) return // protect default session
    setDeletingId(id)
    try {
      await deleteSession(id)
    } finally {
      setDeletingId(null)
    }
  }

  const handleReset = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation()
    if (!window.confirm('Reset this session? All findings, requests and scan data for this session will be permanently deleted.')) return
    setResettingId(id)
    try {
      await apiClient.delete(`/api/sessions/${id}/data`)
      if (id === activeSessionId) {
        useProxyStore.getState().clearRequests()
        useFindingsStore.getState().clear()
      }
      await fetchSessions()
    } catch {
      window.alert('Failed to reset session data')
    } finally {
      setResettingId(null)
    }
  }

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 w-full px-2 py-1.5 rounded text-xs bg-gray-900 border border-gray-700/60 hover:border-purple-700/60 hover:bg-gray-800 transition-all group"
        title="Switch session"
      >
        <Database size={11} className="text-purple-400 shrink-0" />
        <span className="truncate flex-1 text-left text-gray-300 font-medium">{displayName}</span>
        {switching ? (
          <Loader2 size={10} className="animate-spin text-purple-400 shrink-0" />
        ) : (
          <ChevronDown size={10} className={`text-gray-500 shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} />
        )}
      </button>

      {open && (
        <div className="absolute left-0 right-0 top-full mt-1 bg-gray-900 border border-gray-700 rounded-lg shadow-2xl z-50 overflow-hidden">
          {/* Session list */}
          <div className="max-h-52 overflow-y-auto">
            {loading && sessions.length === 0 ? (
              <div className="p-3 text-center text-xs text-gray-500 flex items-center justify-center gap-2">
                <Loader2 size={12} className="animate-spin" />
                Loading…
              </div>
            ) : sessions.length === 0 ? (
              <div className="p-3 text-center text-xs text-gray-500">No sessions yet</div>
            ) : (
              sessions.map((s) => {
                const isActive = s.id === activeSessionId
                const isDefault = s.id === DEFAULT_SESSION_ID
                return (
                  <button
                    key={s.id}
                    onClick={() => handleActivate(s.id)}
                    className={`w-full flex items-center gap-2 px-3 py-2 text-xs text-left transition-colors group/item ${
                      isActive
                        ? 'bg-purple-600/20 text-purple-300'
                        : 'text-gray-300 hover:bg-gray-800'
                    }`}
                  >
                    <Check
                      size={11}
                      className={`shrink-0 ${isActive ? 'text-purple-400' : 'opacity-0'}`}
                    />
                    <span className="truncate flex-1">{s.name}</span>
                    {isDefault && (
                      <span className="text-[9px] text-gray-600 font-mono shrink-0">default</span>
                    )}
                    {!isDefault && (
                      <button
                        onClick={(e) => handleReset(e, s.id)}
                        className="opacity-0 group-hover/item:opacity-100 text-gray-600 hover:text-amber-400 transition-all p-0.5 rounded shrink-0"
                        title="Reset session data (findings, requests, scans)"
                      >
                        {resettingId === s.id ? (
                          <Loader2 size={10} className="animate-spin" />
                        ) : (
                          <Eraser size={10} />
                        )}
                      </button>
                    )}
                    {!isDefault && (
                      <button
                        onClick={(e) => handleDelete(e, s.id)}
                        className="opacity-0 group-hover/item:opacity-100 text-gray-600 hover:text-red-400 transition-all p-0.5 rounded"
                        title="Delete session"
                      >
                        {deletingId === s.id ? (
                          <Loader2 size={10} className="animate-spin" />
                        ) : (
                          <Trash2 size={10} />
                        )}
                      </button>
                    )}
                  </button>
                )
              })
            )}
          </div>

          {/* New session form */}
          <div className="border-t border-gray-800 p-2">
            <div className="flex gap-1">
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') handleCreate() }}
                placeholder="New session name…"
                className="flex-1 min-w-0 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-600"
                autoFocus
              />
              <button
                onClick={handleCreate}
                disabled={creating || !newName.trim()}
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-purple-600 hover:bg-purple-700 text-white text-xs font-medium whitespace-nowrap shrink-0 disabled:opacity-40 transition-colors"
              >
                {creating ? <Loader2 size={10} className="animate-spin" /> : <Plus size={10} />}
                Add
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

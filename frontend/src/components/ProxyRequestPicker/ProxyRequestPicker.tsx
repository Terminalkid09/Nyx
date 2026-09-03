import { useState, useMemo } from 'react'
import { Search } from 'lucide-react'
import { useProxyStore } from '../../store/useProxyStore'
import { NyxRequest } from '../../types'

interface Props {
  value: string
  onChange: (req: NyxRequest | null) => void
  placeholder?: string
}

function matches(req: NyxRequest, q: string) {
  if (!q) return true
  const s = q.toLowerCase()
  return (
    (req.method || '').toLowerCase().includes(s) ||
    (req.host || '').toLowerCase().includes(s) ||
    (req.path || '').toLowerCase().includes(s) ||
    (req.url || '').toLowerCase().includes(s) ||
    (req.response_status != null && String(req.response_status).includes(s))
  )
}

export function ProxyRequestPicker({ value, onChange, placeholder = 'Search requests...' }: Props) {
  const requests = useProxyStore((s) => s.requests)
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)

  const filtered = useMemo(() => {
    const q = query.trim()
    const list = q ? requests.filter((r) => matches(r, q)) : requests
    return list.slice(0, 200)
  }, [requests, query])

  const selected = requests.find((r) => r.id === value) || null

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-2 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 text-left hover:border-gray-600 transition-colors"
      >
        <Search size={11} className="text-gray-500 shrink-0" />
        {selected ? (
          <span className="truncate">
            <span className="font-mono font-bold text-purple-400">{selected.method}</span>{' '}
            <span className="text-gray-400">{selected.host}{selected.path}</span>
          </span>
        ) : (
          <span className="text-gray-500 truncate">Select a proxied request...</span>
        )}
      </button>

      {open && (
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setOpen(false)}
          />
          <div className="absolute left-0 right-0 top-full mt-1 z-50 bg-gray-900 border border-gray-700 rounded-lg shadow-2xl overflow-hidden">
            <div className="flex items-center gap-1.5 px-2 py-1.5 border-b border-gray-800 bg-gray-800/50">
              <Search size={11} className="text-gray-500 shrink-0" />
              <input
                autoFocus
                className="flex-1 min-w-0 bg-transparent outline-none text-xs text-gray-200 placeholder-gray-600"
                placeholder={placeholder}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <span className="text-[10px] text-gray-600 shrink-0">{filtered.length}/{requests.length}</span>
            </div>
            <div className="max-h-56 overflow-y-auto">
              {filtered.length === 0 ? (
                <div className="p-3 text-center text-xs text-gray-600">No requests match</div>
              ) : (
                filtered.map((r) => (
                  <button
                    key={r.id}
                    type="button"
                    onClick={() => {
                      onChange(r)
                      setOpen(false)
                      setQuery('')
                    }}
                    className={`w-full flex items-center gap-2 px-2 py-1.5 text-left text-xs hover:bg-gray-800 transition-colors ${
                      r.id === value ? 'bg-purple-600/10' : ''
                    }`}
                  >
                    <span className="font-mono font-bold text-purple-400 shrink-0 w-12">{r.method}</span>
                    <span className={`font-mono shrink-0 ${r.response_status ? 'text-gray-400' : 'text-gray-600'}`}>
                      {r.response_status ?? '…'}
                    </span>
                    <span className="truncate text-gray-300">{r.host}{r.path}</span>
                  </button>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

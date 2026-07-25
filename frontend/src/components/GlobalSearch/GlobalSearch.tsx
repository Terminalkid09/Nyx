import { useState, useEffect, useRef, useCallback } from 'react'
import { Search, FileText, AlertTriangle } from 'lucide-react'
import { globalSearch } from '../../api/endpoints/search'
import { SearchResult } from '../../types'

export function GlobalSearch() {
  const [query, setQuery] = useState('')
  const [type, setType] = useState('')
  const [results, setResults] = useState<SearchResult[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const performSearch = useCallback(async (q: string, t: string, p: number) => {
    if (!q.trim()) {
      setResults([])
      setTotal(0)
      return
    }
    setLoading(true)
    setError('')
    try {
      const { items, total: tot } = await globalSearch(q.trim(), t || undefined, p)
      setResults(items)
      setTotal(tot)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
      setResults([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      setPage(1)
      performSearch(query, type, 1)
    }, 300)
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [query, type, performSearch])

  useEffect(() => {
    if (page > 1) performSearch(query, type, page)
  }, [page])

  const totalPages = Math.ceil(total / 50)

  const highlightMatch = (text: string) => {
    if (!query.trim()) return text
    const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const parts = text.split(new RegExp(`(${escaped})`, 'gi'))
    return parts.map((part, i) =>
      part.toLowerCase() === query.toLowerCase()
        ? <span key={i} className="bg-yellow-500/30 text-yellow-200 rounded px-0.5">{part}</span>
        : part
    )
  }

  const getTypeIcon = (typeName: string) => {
    switch (typeName) {
      case 'finding': return <AlertTriangle size={14} className="text-orange-400" />
      default: return <FileText size={14} className="text-blue-400" />
    }
  }

  const getTypeBadge = (typeName: string) => {
    const colors: Record<string, string> = {
      request: 'text-purple-400 bg-purple-400/10',
      response: 'text-green-400 bg-green-400/10',
      finding: 'text-orange-400 bg-orange-400/10',
    }
    return colors[typeName] || 'text-gray-400 bg-gray-400/10'
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <Search size={16} />
        <span>Global Search</span>
      </div>
      <div className="flex-1 p-4 space-y-4 overflow-auto">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              className="w-full bg-gray-800 border border-gray-700 rounded pl-7 pr-2 py-1 text-xs text-gray-200"
              placeholder="Search requests, responses, findings..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              autoFocus
            />
          </div>
          <select
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
            value={type}
            onChange={(e) => setType(e.target.value)}
          >
            <option value="">All</option>
            <option value="request">Requests</option>
            <option value="response">Responses</option>
            <option value="finding">Findings</option>
          </select>
        </div>

        {error && <div className="text-xs text-red-400">{error}</div>}

        {loading ? (
          <div className="text-xs text-gray-500">Searching...</div>
        ) : query.trim() && results.length === 0 ? (
          <div className="text-xs text-gray-500">No results found.</div>
        ) : results.length > 0 ? (
          <div className="space-y-2">
            <div className="text-xs text-gray-500">
              {total} result{total !== 1 ? 's' : ''}
            </div>
            {results.map((r, i) => (
              <div
                key={`${r.id}-${i}`}
                className="bg-gray-900 border border-gray-800 rounded p-3 hover:border-gray-700 cursor-pointer"
              >
                <div className="flex items-center gap-2 mb-1">
                  {getTypeIcon(r.type)}
                  <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${getTypeBadge(r.type)}`}>
                    {r.type}
                  </span>
                  {r.url && (
                    <span className="text-xs text-gray-400 font-mono truncate flex-1">{r.url}</span>
                  )}
                </div>
                <div className="text-xs text-gray-300 font-mono">
                  {highlightMatch(r.snippet)}
                </div>
                <div className="text-xs text-gray-600 mt-0.5">
                  Match: {r.match_location}
                </div>
              </div>
            ))}
          </div>
        ) : null}

        {totalPages > 1 && (
          <div className="flex items-center justify-center gap-2">
            <button
              className="px-2 py-1 rounded text-xs bg-gray-800 text-gray-400 hover:bg-gray-700 disabled:opacity-50"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              Prev
            </button>
            <span className="text-xs text-gray-500">
              Page {page} of {totalPages}
            </span>
            <button
              className="px-2 py-1 rounded text-xs bg-gray-800 text-gray-400 hover:bg-gray-700 disabled:opacity-50"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

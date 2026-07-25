import { useState, useMemo } from 'react'

interface ResultRow {
  payload: Record<string, string>
  status: number | null
  size: number
  time_ms: number
  error: string | null
  grep_results: Record<string, boolean>
  extracted: Record<string, string | null>
  request: string | null
  response: string | null
}

interface FuzzResultsProps {
  results: ResultRow[]
  grepMatchNames: string[]
  extractorNames: string[]
  loading?: boolean
}

type SortKey = 'index' | 'status' | 'size' | 'time_ms'

const STATUS_COLORS: Record<string, string> = {
  '2': 'bg-green-500/10 text-green-400 border-green-500/20',
  '3': 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  '4': 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  '5': 'bg-red-500/10 text-red-400 border-red-500/20',
  err: 'bg-red-500/10 text-red-400 border-red-500/20',
}

function getStatusColor(status: number | null): string {
  if (status === null) return STATUS_COLORS.err
  const prefix = String(status)[0]
  return STATUS_COLORS[prefix] || 'bg-gray-500/10 text-gray-400 border-gray-500/20'
}

export function FuzzResults({ results, grepMatchNames, extractorNames, loading }: FuzzResultsProps) {
  const [sortKey, setSortKey] = useState<SortKey>('index')
  const [sortAsc, setSortAsc] = useState(true)
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null)

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc(!sortAsc)
    else { setSortKey(key); setSortAsc(true) }
  }

  const baseline = useMemo(() => {
    if (results.length === 0) return null
    const statusCounts = new Map<number | null, number>()
    for (const r of results) {
      const s = r.status ?? -1
      statusCounts.set(s, (statusCounts.get(s) || 0) + 1)
    }
    let mostCommonStatus: number | null = -1
    let maxCount = 0
    for (const [s, c] of statusCounts) {
      if (c > maxCount) { maxCount = c; mostCommonStatus = s }
    }
    const baselineResults = results.filter(r => (r.status ?? -1) === mostCommonStatus)
    const avgSize = baselineResults.length > 0
      ? Math.round(baselineResults.reduce((a, r) => a + r.size, 0) / baselineResults.length)
      : 0
    return {
      status: mostCommonStatus === -1 ? null : mostCommonStatus,
      avgSize,
      sizeThreshold: Math.max(Math.round(avgSize * 0.2), 50),
    }
  }, [results])

  const filtered = useMemo(() => {
    let arr = [...results]
    if (statusFilter !== 'all') {
      if (statusFilter === 'error') arr = arr.filter(r => r.status === null)
      else if (statusFilter === '2xx') arr = arr.filter(r => r.status !== null && r.status >= 200 && r.status < 300)
      else if (statusFilter === '3xx') arr = arr.filter(r => r.status !== null && r.status >= 300 && r.status < 400)
      else if (statusFilter === '4xx') arr = arr.filter(r => r.status !== null && r.status >= 400 && r.status < 500)
      else if (statusFilter === '5xx') arr = arr.filter(r => r.status !== null && r.status >= 500 && r.status < 600)
      else if (statusFilter === 'anomaly') {
        arr = arr.filter(r => {
          if (!baseline) return false
          const statusMatch = (r.status ?? -1) === (baseline.status ?? -1)
          const sizeDiff = Math.abs(r.size - baseline.avgSize)
          return !statusMatch || sizeDiff > baseline.sizeThreshold
        })
      }
    }
    arr.sort((a, b) => {
      let cmp = 0
      if (sortKey === 'index') cmp = results.indexOf(a) - results.indexOf(b)
      else if (sortKey === 'status') cmp = (a.status ?? 0) - (b.status ?? 0)
      else if (sortKey === 'size') cmp = a.size - b.size
      else if (sortKey === 'time_ms') cmp = a.time_ms - b.time_ms
      return sortAsc ? cmp : -cmp
    })
    return arr
  }, [results, sortKey, sortAsc, statusFilter, baseline])

  const isAnomaly = (row: ResultRow): boolean => {
    if (!baseline) return false
    const statusMatch = (row.status ?? -1) === (baseline.status ?? -1)
    const sizeDiff = Math.abs(row.size - baseline.avgSize)
    return !statusMatch || sizeDiff > baseline.sizeThreshold
  }

  const statusBadge = (status: number | null) => {
    if (status === null) return <span className="text-red-400 font-bold">ERR</span>
    const color = getStatusColor(status)
    return <span className={`px-1 py-0.5 rounded text-[10px] font-mono ${color}`}>{status}</span>
  }

  const sortIcon = (key: SortKey) => {
    if (sortKey !== key) return <span className="text-gray-600 ml-1">↕</span>
    return <span className="ml-1">{sortAsc ? '↑' : '↓'}</span>
  }

  const payloadDisplay = (payload: Record<string, string>) => {
    const entries = Object.entries(payload)
    if (entries.length === 0) return <span className="text-gray-600">—</span>
    return (
      <span className="truncate block" title={JSON.stringify(payload)}>
        {entries.map(([k, v], i) => (
          <span key={k}>
            {i > 0 && <span className="text-gray-700">, </span>}
            <span className="text-purple-400">{k}</span>
            <span className="text-gray-600">=</span>
            <span className="text-gray-200">{v || <span className="text-gray-600">∅</span>}</span>
          </span>
        ))}
      </span>
    )
  }

  const statusSummary = useMemo(() => {
    const counts: Record<string, number> = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, error: 0 }
    for (const r of results) {
      if (r.status === null) counts.error++
      else if (r.status < 300) counts['2xx']++
      else if (r.status < 400) counts['3xx']++
      else if (r.status < 500) counts['4xx']++
      else counts['5xx']++
    }
    return Object.entries(counts).filter(([_, c]) => c > 0)
  }, [results])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-purple-400 text-sm animate-pulse">Fuzzing in progress...</div>
      </div>
    )
  }

  if (results.length === 0) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-gray-500 text-sm">No results yet.</div>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {/* Summary bar */}
      <div className="flex items-center gap-3 text-xs">
        <span className="text-gray-400">{results.length} requests</span>
        <span className="text-gray-700">|</span>
        {statusSummary.map(([label, count]) => (
          <span key={label} className={`text-[10px] px-1.5 py-0.5 rounded ${
            label === 'error' ? 'bg-red-500/10 text-red-400' :
            label === '5xx' ? 'bg-red-500/10 text-red-400' :
            label === '4xx' ? 'bg-orange-500/10 text-orange-400' :
            label === '3xx' ? 'bg-blue-500/10 text-blue-400' :
            'bg-green-500/10 text-green-400'
          }`}>
            {label}: {count}
          </span>
        ))}
        {baseline && (
          <>
            <span className="text-gray-700">|</span>
            <span className="text-gray-500">baseline: {baseline.status || 'ERR'} ~{baseline.avgSize}B</span>
          </>
        )}
        <div className="flex-1" />
        <label className="text-gray-500">Filter:</label>
        <select
          className="bg-gray-800 border border-gray-700 rounded px-2 py-0.5 text-xs text-gray-200"
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
        >
          <option value="all">All</option>
          <option value="anomaly">Anomalies</option>
          <option value="2xx">2xx</option>
          <option value="3xx">3xx</option>
          <option value="4xx">4xx</option>
          <option value="5xx">5xx</option>
          <option value="error">Error</option>
        </select>
      </div>

      {/* Results table */}
      <div className="overflow-x-auto">
        <table className="w-full text-xs border-collapse">
          <thead>
            <tr className="text-gray-500 border-b border-gray-800">
              <th className="text-left py-1 px-1 cursor-pointer hover:text-gray-300 w-8" onClick={() => handleSort('index')}>
                # {sortIcon('index')}
              </th>
              <th className="text-left py-1 px-1 text-gray-400">Payload</th>
              <th className="text-left py-1 px-1 cursor-pointer hover:text-gray-300 w-16" onClick={() => handleSort('status')}>
                Status {sortIcon('status')}
              </th>
              <th className="text-right py-1 px-1 cursor-pointer hover:text-gray-300 w-16" onClick={() => handleSort('size')}>
                Length {sortIcon('size')}
              </th>
              <th className="text-right py-1 px-1 cursor-pointer hover:text-gray-300 w-16" onClick={() => handleSort('time_ms')}>
                Time {sortIcon('time_ms')}
              </th>
              {grepMatchNames.map(name => (
                <th key={name} className="text-center py-1 px-1 text-gray-400 w-10">{name}</th>
              ))}
              {extractorNames.map(name => (
                <th key={name} className="text-left py-1 px-1 text-gray-400 min-w-[80px]">{name}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((row) => {
              const originalIndex = results.indexOf(row)
              const isExpanded = expandedIndex === originalIndex
              const anomaly = isAnomaly(row)
              return (
                <tr
                  key={originalIndex}
                  className={`border-b border-gray-800/50 cursor-pointer transition-colors ${
                    anomaly ? 'bg-yellow-500/5 hover:bg-yellow-500/10' : 'hover:bg-gray-800/30'
                  } ${isExpanded ? 'bg-gray-800/50' : ''}`}
                  onClick={() => setExpandedIndex(isExpanded ? null : originalIndex)}
                >
                  <td className="py-1 px-1 text-gray-500">
                    <span className="flex items-center gap-1">
                      {anomaly && <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" title="Anomaly" />}
                      {originalIndex}
                    </span>
                  </td>
                  <td className="py-1 px-1 max-w-[180px]">{payloadDisplay(row.payload)}</td>
                  <td className="py-1 px-1">{statusBadge(row.status)}</td>
                  <td className="py-1 px-1 text-right text-gray-400 font-mono">
                    {row.size > 0 ? row.size.toLocaleString() : '—'}
                  </td>
                  <td className="py-1 px-1 text-right text-gray-400 font-mono">
                    {row.time_ms > 0 ? `${row.time_ms}` : '—'}
                  </td>
                  {grepMatchNames.map(name => (
                    <td key={name} className="py-1 px-1 text-center">
                      {row.grep_results[name] === true
                        ? <span className="text-green-400 font-bold">✓</span>
                        : row.grep_results[name] === false
                        ? <span className="text-red-500">✗</span>
                        : <span className="text-gray-600">—</span>}
                    </td>
                  ))}
                  {extractorNames.map(name => (
                    <td key={name} className="py-1 px-1 text-gray-300 truncate max-w-[100px]" title={row.extracted[name] ?? ''}>
                      {row.extracted[name] ?? <span className="text-gray-600">—</span>}
                    </td>
                  ))}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Expanded detail */}
      {expandedIndex !== null && results[expandedIndex] && (
        <div className="bg-gray-900 border border-gray-800 rounded p-3 text-xs font-mono">
          <div className="flex items-center justify-between mb-2">
            <span className="text-gray-400">Request #{expandedIndex}</span>
            <button className="text-purple-400 hover:text-purple-300" onClick={() => setExpandedIndex(null)}>
              Close
            </button>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-gray-500 text-[10px] uppercase mb-1">Request</div>
              <pre className="text-gray-300 whitespace-pre-wrap break-all max-h-48 overflow-y-auto bg-gray-950 p-2 rounded border border-gray-800">
                {results[expandedIndex].request || 'N/A'}
              </pre>
            </div>
            <div>
              <div className="text-gray-500 text-[10px] uppercase mb-1">Response</div>
              <pre className="text-gray-300 whitespace-pre-wrap break-all max-h-48 overflow-y-auto bg-gray-950 p-2 rounded border border-gray-800">
                {results[expandedIndex].response || results[expandedIndex].error || 'N/A'}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

import { useState } from 'react'
import { apiClient } from '../../api/client'
import { useProxyStore } from '../../store/useProxyStore'

const CHECKS = [
  { id: 'sqli', label: 'SQL Injection', severity: 'high' },
  { id: 'xss', label: 'Cross-Site Scripting', severity: 'high' },
  { id: 'ssrf', label: 'SSRF', severity: 'critical' },
  { id: 'open_redirect', label: 'Open Redirect', severity: 'medium' },
  { id: 'lfi', label: 'Local File Inclusion', severity: 'high' },
  { id: 'idor', label: 'Insecure Direct Object Ref.', severity: 'high' },
  { id: 'ssti', label: 'Server-Side Template Inj.', severity: 'high' },
  { id: 'xxe', label: 'XML External Entity', severity: 'high' },
]

export function ActiveScanner() {
  const requests = useProxyStore((s) => s.requests)
  const [selectedReqId, setSelectedReqId] = useState('')
  const [selectedChecks, setSelectedChecks] = useState<string[]>([])
  const [results, setResults] = useState<any[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const toggleCheck = (id: string) => {
    setSelectedChecks((prev) =>
      prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id],
    )
  }

  function extractParams(url: string): string[] {
    try {
      const u = new URL(url)
      return [...u.searchParams.keys()]
    } catch {
      return []
    }
  }

  const runScan = async () => {
    const req = requests.find((r) => r.id === selectedReqId)
    if (!req || selectedChecks.length === 0) return

    setLoading(true)
    setError('')
    setResults(null)

    const params = extractParams(req.url)
    try {
      const { data } = await apiClient.post('/api/active-scanner/run', {
        base_request: {
          method: req.method,
          url: req.url,
          headers: req.request_headers,
          body: req.request_body,
        },
        target_params: params.length > 0 ? params : [''],
        checks: selectedChecks,
      })
      setResults(data.results || [])
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300">
        Active Scanner
      </div>
      <div className="flex-1 p-4 space-y-4 overflow-auto">
        <div>
          <label className="text-xs text-gray-500 block mb-1">Select Request</label>
          <select
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
            value={selectedReqId}
            onChange={(e) => setSelectedReqId(e.target.value)}
          >
            <option value="">— choose a request from Proxy —</option>
            {(requests || []).slice(0, 100).map((r) => (
              <option key={r.id} value={r.id}>
                {r.method} {r.host}{r.path}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="text-xs text-gray-500 block mb-1">Checks</label>
          <div className="space-y-1">
            {CHECKS.map((c) => (
              <label key={c.id} className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={selectedChecks.includes(c.id)}
                  onChange={() => toggleCheck(c.id)}
                  className="accent-purple-500"
                />
                {c.label}
              </label>
            ))}
          </div>
        </div>

        <button
          className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium disabled:opacity-50"
          onClick={runScan}
          disabled={loading || !selectedReqId || selectedChecks.length === 0}
        >
          {loading ? 'Scanning...' : 'Run Active Scan'}
        </button>

        {error && <div className="text-red-400 text-xs">{error}</div>}

        {results && results.length === 0 && (
          <div className="text-green-400 text-xs">No vulnerabilities found.</div>
        )}

        {results && results.length > 0 && (
          <div className="space-y-2">
            {results.map((r, i) => (
              <div key={i} className="bg-gray-900 border border-gray-800 rounded p-3">
                <div className="text-xs font-bold text-orange-400">{r.title}</div>
                <div className="text-xs text-gray-400 mt-1">{r.description}</div>
                {r.evidence && (
                  <pre className="text-xs text-gray-500 mt-1 bg-gray-950 p-2 rounded">{r.evidence}</pre>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

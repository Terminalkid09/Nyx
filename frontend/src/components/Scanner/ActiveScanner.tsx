import { useState, useEffect } from 'react'
import { useSearchParams, useLocation } from 'react-router-dom'
import { apiClient } from '../../api/client'
import { useProxyStore } from '../../store/useProxyStore'
import { ProxyRequestPicker } from '../ProxyRequestPicker/ProxyRequestPicker'

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
  const [searchParams] = useSearchParams()
  const location = useLocation()
  const navState = (location.state || {}) as Record<string, any>
  const queryUrl = searchParams.get('url') || navState.url || ''

  const [selectedReqId, setSelectedReqId] = useState('')
  const [customUrl, setCustomUrl] = useState(queryUrl)
  const [customMethod, setCustomMethod] = useState(navState.method || 'GET')
  const [customHeaders, setCustomHeaders] = useState<string>(
    typeof navState.headers === 'string'
      ? navState.headers
      : Object.entries(navState.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n'),
  )
  const [customBody, setCustomBody] = useState(navState.body || '')
  const [useCustomUrl, setUseCustomUrl] = useState(!!queryUrl || !!navState.url)
  const [selectedChecks, setSelectedChecks] = useState<string[]>([])
  const [results, setResults] = useState<any[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (customUrl && !selectedReqId) {
      const found = (requests || []).find(r => r.url?.includes(customUrl))
      if (found) setSelectedReqId(found.id)
    }
  }, [customUrl, requests, selectedReqId])

  useEffect(() => {
    if (navState.cwe && navState.cwe.includes('89')) {
      setSelectedChecks(prev => prev.includes('sqli') ? prev : [...prev, 'sqli'])
    }
  }, [navState.cwe])

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
    let scanUrl: string
    let scanMethod: string
    let scanHeaders: Record<string, string>
    let scanBody: string

    if (useCustomUrl) {
      if (!customUrl) { setError('Enter a target URL'); return }
      scanUrl = customUrl
      scanMethod = customMethod || 'GET'
      scanHeaders = {}
      const seen = new Set<string>()
      customHeaders.split('\n').forEach((line) => {
        const idx = line.indexOf(':')
        if (idx > 0) {
          const k = line.slice(0, idx).trim()
          const v = line.slice(idx + 1).trim()
          if (k && !seen.has(k.toLowerCase())) { seen.add(k.toLowerCase()); scanHeaders[k] = v }
        }
      })
      scanBody = customBody
    } else {
      const req = requests.find((r) => r.id === selectedReqId)
      if (!req) {
        setError('Selected request not found. It may have been removed from the log.')
        return
      }
      scanUrl = req.url
      scanMethod = req.method
      scanHeaders = req.request_headers || {}
      scanBody = req.request_body || ''
    }
    if (selectedChecks.length === 0) return

    setLoading(true)
    setError('')
    setResults(null)

    const params = extractParams(scanUrl)
    try {
      const { data } = await apiClient.post('/api/active-scanner/run', {
        base_request: {
          method: scanMethod,
          url: scanUrl,
          headers: scanHeaders,
          body: scanBody,
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
        <div className="flex items-center gap-2 mb-2">
          <label className="flex items-center gap-1.5 text-xs text-gray-500 cursor-pointer">
            <input type="checkbox" checked={useCustomUrl} onChange={() => setUseCustomUrl(!useCustomUrl)} className="accent-purple-500" />
            Custom URL
          </label>
        </div>
        {useCustomUrl ? (
          <div className="space-y-3">
            <div>
              <label className="text-xs text-gray-500 block mb-1">Target URL</label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
                value={customUrl}
                onChange={(e) => setCustomUrl(e.target.value)}
                placeholder="https://example.com/page?param=value"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-gray-500 block mb-1">Method</label>
                <input
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
                  value={customMethod}
                  onChange={(e) => setCustomMethod(e.target.value)}
                  placeholder="GET"
                />
              </div>
              <div>
                <label className="text-xs text-gray-500 block mb-1">Body</label>
                <input
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
                  value={customBody}
                  onChange={(e) => setCustomBody(e.target.value)}
                  placeholder="request body"
                />
              </div>
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">Headers</label>
              <textarea
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono h-16"
                value={customHeaders}
                onChange={(e) => setCustomHeaders(e.target.value)}
                placeholder={'Host: example.com\r\nCookie: x=y'}
              />
            </div>
          </div>
        ) : (
          <div>
            <label className="text-xs text-gray-500 block mb-1">Select Request</label>
            <ProxyRequestPicker
              value={selectedReqId}
              onChange={(req) => req && setSelectedReqId(req.id)}
            />
          </div>
        )}

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

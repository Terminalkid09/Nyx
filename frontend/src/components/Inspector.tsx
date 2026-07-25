import { useState } from 'react'
import { apiClient } from '../api/client'

interface ParsedParam {
  name: string
  value: string
  suspicious: boolean
}

interface CookieInfo {
  name: string
  value: string
  domain: string | null
  path: string | null
  secure: boolean
  http_only: boolean
}

interface AnalyzeRequestResult {
  parsed_params: ParsedParam[]
  cookies: CookieInfo[]
  content_type: string
  body_size: number
  param_count: number
  suspicious_params: ParsedParam[]
  headers_count: number
  has_body: boolean
}

interface SecurityHeaders {
  content_security_policy: string | null
  x_content_type_options: string | null
  x_frame_options: string | null
  strict_transport_security: string | null
  x_xss_protection: string | null
}

interface CacheHeaders {
  cache_control: string | null
  pragma: string | null
  expires: string | null
}

interface AnalyzeResponseResult {
  content_type: string
  content_length: number
  cookies_set: CookieInfo[]
  security_headers: SecurityHeaders
  cache_headers: CacheHeaders
  server_info: string
  suspicious_content: string[]
}

interface InspectResult {
  request_analysis: AnalyzeRequestResult | null
  response_analysis: AnalyzeResponseResult | null
}

function SecurityBadge({ present, label }: { present: boolean; label: string }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className={present ? 'text-green-400' : 'text-red-400'}>
        {present ? '✓' : '✗'}
      </span>
      <span className="text-gray-300">{label}</span>
    </div>
  )
}

export function Inspector() {
  const [requestRaw, setRequestRaw] = useState('')
  const [responseRaw, setResponseRaw] = useState('')
  const [result, setResult] = useState<InspectResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const parseRaw = (raw: string): { method: string; url: string; headers: Record<string, string>; body: string | null } => {
    const lines = raw.split('\n')
    const first = lines[0] || ''
    const parts = first.split(' ')
    const method = parts[0] || 'GET'
    const url = parts[1] || ''
    const headerEnd = lines.findIndex(l => l.trim() === '')
    const headerLines = headerEnd > 0 ? lines.slice(1, headerEnd) : lines.slice(1)
    const headers: Record<string, string> = {}
    for (const hl of headerLines) {
      const idx = hl.indexOf(':')
      if (idx > 0) {
        headers[hl.slice(0, idx).trim()] = hl.slice(idx + 1).trim()
      }
    }
    const body = headerEnd > 0 ? lines.slice(headerEnd + 1).join('\n').trim() : null
    return { method, url, headers, body: body || null }
  }

  const parseRawResponse = (raw: string): { status_code: number; headers: Record<string, string>; body: string | null } => {
    const lines = raw.split('\n')
    const first = lines[0] || ''
    const statusCode = parseInt(first.split(' ')[1]) || 200
    const headerEnd = lines.findIndex(l => l.trim() === '')
    const headerLines = headerEnd > 0 ? lines.slice(1, headerEnd) : lines.slice(1)
    const headers: Record<string, string> = {}
    for (const hl of headerLines) {
      const idx = hl.indexOf(':')
      if (idx > 0) {
        headers[hl.slice(0, idx).trim()] = hl.slice(idx + 1).trim()
      }
    }
    const body = headerEnd > 0 ? lines.slice(headerEnd + 1).join('\n').trim() : null
    return { status_code: statusCode, headers, body: body || null }
  }

  const handleAnalyze = async () => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const reqData = parseRaw(requestRaw)
      let respData = null
      if (responseRaw.trim()) {
        respData = parseRawResponse(responseRaw)
      }
      const { data } = await apiClient.post('/api/inspector/inspect', {
        request: reqData,
        response: respData,
      })
      setResult(data)
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300">Inspector</div>

      <div className="flex-1 flex gap-2 p-2 overflow-hidden">
        <div className="flex-1 flex flex-col gap-2">
          <div className="text-xs text-gray-400 font-medium">Request</div>
          <textarea
            className="flex-1 bg-gray-900 border border-gray-700 rounded p-2 text-xs text-gray-200 font-mono resize-none"
            placeholder={`GET /api/endpoint HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\n\nbody content`}
            value={requestRaw}
            onChange={e => setRequestRaw(e.target.value)}
          />
        </div>
        <div className="flex-1 flex flex-col gap-2">
          <div className="text-xs text-gray-400 font-medium">Response (optional)</div>
          <textarea
            className="flex-1 bg-gray-900 border border-gray-700 rounded p-2 text-xs text-gray-200 font-mono resize-none"
            placeholder={`HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"key": "value"}`}
            value={responseRaw}
            onChange={e => setResponseRaw(e.target.value)}
          />
        </div>
      </div>

      <div className="px-2 pb-2 flex gap-2">
        <button
          onClick={handleAnalyze}
          disabled={loading || !requestRaw.trim()}
          className="px-4 py-1.5 rounded text-xs bg-purple-600 text-white hover:bg-purple-500 disabled:opacity-50"
        >
          {loading ? 'Analyzing...' : 'Analyze'}
        </button>
        <button
          onClick={() => { setRequestRaw(''); setResponseRaw(''); setResult(null); setError(null) }}
          className="px-4 py-1.5 rounded text-xs bg-gray-800 text-gray-400 hover:text-white"
        >
          Clear
        </button>
      </div>

      {error && (
        <div className="px-2 pb-2 text-xs text-red-400">{error}</div>
      )}

      {result && (
        <div className="border-t border-gray-800 overflow-auto" style={{ maxHeight: '50%' }}>
          <div className="flex">
            {result.request_analysis && (
              <div className="flex-1 p-3 border-r border-gray-800">
                <div className="text-xs font-medium text-gray-300 mb-2">Request Analysis</div>

                <div className="space-y-3 text-xs">
                  {result.request_analysis.content_type && (
                    <div><span className="text-gray-500">Content-Type:</span> <span className="text-gray-300">{result.request_analysis.content_type}</span></div>
                  )}
                  <div><span className="text-gray-500">Body Size:</span> <span className="text-gray-300">{result.request_analysis.body_size} bytes</span></div>
                  <div><span className="text-gray-500">Param Count:</span> <span className="text-gray-300">{result.request_analysis.param_count}</span></div>
                  <div><span className="text-gray-500">Headers Count:</span> <span className="text-gray-300">{result.request_analysis.headers_count}</span></div>
                  <div><span className="text-gray-500">Has Body:</span> <span className="text-gray-300">{result.request_analysis.has_body ? 'Yes' : 'No'}</span></div>

                  {result.request_analysis.parsed_params.length > 0 && (
                    <div>
                      <div className="text-gray-400 mb-1">Parameters</div>
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="text-gray-500 border-b border-gray-800">
                            <th className="text-left pr-2">Name</th>
                            <th className="text-left pr-2">Value</th>
                            <th className="text-left">Suspicious</th>
                          </tr>
                        </thead>
                        <tbody>
                          {result.request_analysis.parsed_params.map((p, i) => (
                            <tr key={i} className="border-b border-gray-900">
                              <td className="pr-2 text-gray-300">{p.name}</td>
                              <td className="pr-2 text-gray-400 truncate max-w-[200px]">{p.value}</td>
                              <td className={p.suspicious ? 'text-red-400' : 'text-green-400'}>{p.suspicious ? 'Yes' : 'No'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {result.request_analysis.suspicious_params.length > 0 && (
                    <div>
                      <div className="text-red-400 mb-1">Suspicious Parameters</div>
                      {result.request_analysis.suspicious_params.map((p, i) => (
                        <div key={i} className="text-red-300">{p.name}: {p.value}</div>
                      ))}
                    </div>
                  )}

                  {result.request_analysis.cookies.length > 0 && (
                    <div>
                      <div className="text-gray-400 mb-1">Cookies</div>
                      {result.request_analysis.cookies.map((c, i) => (
                        <div key={i} className="text-gray-300">{c.name}={c.value}</div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {result.response_analysis && (
              <div className="flex-1 p-3">
                <div className="text-xs font-medium text-gray-300 mb-2">Response Analysis</div>

                <div className="space-y-3 text-xs">
                  <div><span className="text-gray-500">Content-Type:</span> <span className="text-gray-300">{result.response_analysis.content_type}</span></div>
                  <div><span className="text-gray-500">Content-Length:</span> <span className="text-gray-300">{result.response_analysis.content_length}</span></div>
                  {result.response_analysis.server_info && (
                    <div><span className="text-gray-500">Server:</span> <span className="text-gray-300">{result.response_analysis.server_info}</span></div>
                  )}

                  <div>
                    <div className="text-gray-400 mb-1">Security Headers</div>
                    <SecurityBadge present={!!result.response_analysis.security_headers.content_security_policy} label="Content-Security-Policy" />
                    <SecurityBadge present={!!result.response_analysis.security_headers.x_content_type_options} label="X-Content-Type-Options" />
                    <SecurityBadge present={!!result.response_analysis.security_headers.x_frame_options} label="X-Frame-Options" />
                    <SecurityBadge present={!!result.response_analysis.security_headers.strict_transport_security} label="Strict-Transport-Security" />
                    <SecurityBadge present={!!result.response_analysis.security_headers.x_xss_protection} label="X-XSS-Protection" />
                  </div>

                  <div>
                    <div className="text-gray-400 mb-1">Cache Headers</div>
                    {result.response_analysis.cache_headers.cache_control && <div className="text-gray-300">Cache-Control: {result.response_analysis.cache_headers.cache_control}</div>}
                    {result.response_analysis.cache_headers.pragma && <div className="text-gray-300">Pragma: {result.response_analysis.cache_headers.pragma}</div>}
                    {result.response_analysis.cache_headers.expires && <div className="text-gray-300">Expires: {result.response_analysis.cache_headers.expires}</div>}
                  </div>

                  {result.response_analysis.cookies_set.length > 0 && (
                    <div>
                      <div className="text-gray-400 mb-1">Cookies Set</div>
                      {result.response_analysis.cookies_set.map((c, i) => (
                        <div key={i} className="text-gray-300">{c.name}={c.value}</div>
                      ))}
                    </div>
                  )}

                  {result.response_analysis.suspicious_content.length > 0 && (
                    <div>
                      <div className="text-red-400 mb-1">Suspicious Content</div>
                      {result.response_analysis.suspicious_content.map((s, i) => (
                        <div key={i} className="text-red-300">{s}</div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

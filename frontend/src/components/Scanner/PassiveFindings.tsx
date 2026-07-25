import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { ExternalLink, RefreshCw } from 'lucide-react'
import { apiClient } from '../../api/client'
import { useFindingsStore } from '../../store/useFindingsStore'
import { useProxyStore } from '../../store/useProxyStore'
import { NyxFinding } from '../../types'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10',
  high: 'text-orange-400 bg-orange-400/10',
  medium: 'text-yellow-400 bg-yellow-400/10',
  low: 'text-green-400 bg-green-400/10',
  info: 'text-gray-400 bg-gray-400/10',
}

export function PassiveFindings() {
  const findings = useFindingsStore((s) => s.findings)
  const requests = useProxyStore((s) => s.requests)
  const navigate = useNavigate()
  const [retesting, setRetesting] = useState<Record<string, 'idle' | 'loading' | 'confirmed' | 'fixed' | 'error'>>({})

  const sendToRepeater = useCallback(async (f: NyxFinding) => {
    const req = requests.find((r) => r.id === f.request_id)
    if (!req) return
    try {
      await apiClient.post('/api/repeater/tabs', {
        method: req.method,
        url: req.url,
        headers: req.request_headers,
        body: req.request_body,
      })
      navigate('/repeater')
    } catch {
      // silently fail
    }
  }, [requests, navigate])

  const retest = useCallback(async (findingId: string) => {
    setRetesting((prev) => ({ ...prev, [findingId]: 'loading' }))
    try {
      const { data } = await apiClient.get(`/api/triage/findings/${findingId}/retest`)
      const status: string = data.status || data.result || 'error'
      setRetesting((prev) => ({
        ...prev,
        [findingId]: status === 'confirmed' ? 'confirmed' : status === 'fixed' ? 'fixed' : 'error',
      }))
    } catch {
      setRetesting((prev) => ({ ...prev, [findingId]: 'error' }))
    }
  }, [])

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <span>Passive Scanner Findings</span>
        <span className="text-xs text-gray-500">({findings.length} total)</span>
      </div>
      <div className="flex-1 overflow-auto p-2 space-y-2">
        {findings.length === 0 ? (
          <div className="text-gray-500 text-xs p-4 text-center">
            No findings yet. Traffic is analyzed automatically as it passes through the proxy.
          </div>
        ) : (
          findings.map((f) => {
            const retestState = retesting[f.id] || 'idle'
            const req = requests.find((r) => r.id === f.request_id)
            return (
              <div
                key={f.id}
                className="bg-gray-900 border border-gray-800 rounded p-3"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className={`text-xs font-bold px-1.5 py-0.5 rounded ${
                      SEVERITY_COLORS[f.severity] || ''
                    }`}
                  >
                    {f.severity.toUpperCase()}
                  </span>
                  <span className="text-sm font-medium text-gray-200">{f.title}</span>
                  {f.cwe && (
                    <span className="text-xs text-gray-500 ml-auto">{f.cwe}</span>
                  )}
                  <div className="flex items-center gap-1 ml-auto">
                    {req && (
                      <button
                        onClick={() => sendToRepeater(f)}
                        className="text-gray-500 hover:text-purple-400 transition-colors p-1"
                        title="Send to Repeater"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    )}
                    <button
                      onClick={() => retest(f.id)}
                      disabled={retestState === 'loading'}
                      className="text-gray-500 hover:text-purple-400 transition-colors p-1 disabled:opacity-50"
                      title="Retest"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${retestState === 'loading' ? 'animate-spin' : ''}`} />
                    </button>
                  </div>
                </div>
                <p className="text-xs text-gray-400">{f.description}</p>
                {f.evidence && (
                  <pre className="mt-2 text-xs text-gray-500 bg-gray-950 p-2 rounded overflow-x-auto">
                    {f.evidence}
                  </pre>
                )}
                {f.remediation && (
                  <div className="mt-2 text-xs text-green-400">
                    Fix: {f.remediation}
                  </div>
                )}
                {retestState !== 'idle' && retestState !== 'loading' && (
                  <div
                    className={`mt-2 text-xs px-2 py-1 rounded inline-block ${
                      retestState === 'confirmed'
                        ? 'text-green-400 bg-green-400/10'
                        : retestState === 'fixed'
                        ? 'text-red-400 bg-red-400/10'
                        : 'text-yellow-400 bg-yellow-400/10'
                    }`}
                  >
                    {retestState === 'confirmed' && 'Confirmed'}
                    {retestState === 'fixed' && 'Fixed'}
                    {retestState === 'error' && 'Error'}
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}

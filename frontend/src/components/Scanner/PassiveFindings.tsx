import { useState, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { ExternalLink, RefreshCw } from 'lucide-react'
import { apiClient } from '../../api/client'
import { useFindingsStore } from '../../store/useFindingsStore'
import { useProxyStore } from '../../store/useProxyStore'
import { useFuzzerStore } from '../../store/useFuzzerStore'
import { useAutoExploitStore } from '../../store/useAutoExploitStore'
import { useSessionStore } from '../../store/useSessionStore'
import { NyxFinding } from '../../types'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10',
  high: 'text-orange-400 bg-orange-400/10',
  medium: 'text-yellow-400 bg-yellow-400/10',
  low: 'text-green-400 bg-green-400/10',
  info: 'text-gray-400 bg-gray-400/10',
}

export function PassiveFindings() {
  const { findings, setFindings } = useFindingsStore()
  const { setFuzzerTarget } = useFuzzerStore()
  const { setTarget: setAutoExploitTarget } = useAutoExploitStore()
  const requests = useProxyStore((s) => s.requests)
  const activeSessionId = useSessionStore((s) => s.activeSessionId)
  
  const [openMenuId, setOpenMenuId] = useState<string | null>(null)
  const navigate = useNavigate()
  const [retesting, setRetesting] = useState<Record<string, 'idle' | 'loading' | 'confirmed' | 'fixed' | 'error'>>({})

  useEffect(() => {
    const handleOutsideClick = () => setOpenMenuId(null)
    window.addEventListener('click', handleOutsideClick)
    return () => window.removeEventListener('click', handleOutsideClick)
  }, [])

  // Fetch history for the active session
  useEffect(() => {
    if (!activeSessionId) return
    let mounted = true
    const fetchHistory = async () => {
      try {
        const { data } = await apiClient.get('/api/findings', {
          params: { session_id: activeSessionId, per_page: 500 }
        })
        if (mounted) {
          setFindings(data.items)
        }
      } catch (err) {
        console.error('Failed to load findings history', err)
      }
    }
    fetchHistory()
    return () => { mounted = false }
  }, [activeSessionId, setFindings])

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
                  <div className="relative inline-block text-left ml-2" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        setOpenMenuId(openMenuId === f.id ? null : f.id)
                      }}
                      className="text-gray-500 hover:text-gray-300 px-2 py-1 transition-colors"
                    >
                      ⋮
                    </button>
                    
                    {openMenuId === f.id && (
                      <div className="absolute right-0 top-6 w-40 bg-gray-800 border border-gray-700 rounded shadow-xl z-50 flex flex-col py-1 text-xs text-left">
                        <button
                          className="text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200"
                          onClick={() => {
                            setOpenMenuId(null)
                            sendToRepeater(f)
                          }}
                        >
                          Send to Repeater
                        </button>
                        
                        <button
                          className="text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200"
                          onClick={() => {
                            setOpenMenuId(null)
                            if (req) {
                              const body = req.request_body ? `\r\n${req.request_body}` : ''
                              setFuzzerTarget(req.id, `${req.method || 'GET'} ${req.path || f.url} HTTP/1.1\r\nHost: ${req.host || 'localhost'}\r\n${body}`)
                              navigate('/fuzzer')
                            }
                          }}
                        >
                          Send to Fuzzer
                        </button>
                        
                        <button
                          className="text-left px-3 py-1.5 hover:bg-gray-700 text-purple-300 font-medium"
                          onClick={() => {
                            setOpenMenuId(null)
                            setAutoExploitTarget({
                              type: 'finding',
                              id: f.id,
                              url: f.url || '',
                              cwe: f.cwe || undefined,
                              param: f.param || undefined,
                            })
                            navigate('/auto-exploit')
                          }}
                        >
                          Send to Auto-Exploit
                        </button>
                      </div>
                    )}
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

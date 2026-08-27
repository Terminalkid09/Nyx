import { useState, useEffect, useRef, useCallback } from 'react'
import { useLocation } from 'react-router-dom'
import { useProxyStore } from '../../store/useProxyStore'
import { useSessionStore } from '../../store/useSessionStore'
import {
  createFuzzJob,
  getFuzzJob,
  fetchWordlists,
  previewFuzzJob,
  fetchAttackTypes,
  fetchProcessors,
  cancelFuzzJob,
} from '../../api/endpoints/fuzzer'
import { FuzzResults } from './FuzzResults'

interface PositionConfig {
  name: string
  wordlist_path: string
  processors: string[]
}

interface GrepMatch {
  name: string
  pattern: string
  is_regex: boolean
}

interface Extractor {
  name: string
  pattern: string
  is_regex: boolean
  group: number
}

import { useFuzzerStore } from '../../store/useFuzzerStore'
import { useJobsStore } from '../../store/useJobsStore'
import { ProxyRequestPicker } from '../ProxyRequestPicker/ProxyRequestPicker'

const DEFAULT_SESSION_ID = '00000000-0000-0000-0000-000000000001'

export function Fuzzer() {
  const requests = useProxyStore((s) => s.requests)
  const { activeSessionId } = useSessionStore()
  const { selectedReqId, template, setFuzzerTarget } = useFuzzerStore()
  const { jobs: storedJobs, setJob: storeJob, clearJob: clearStoredJob } = useJobsStore()
  const location = useLocation()
  const navState = (location.state || {}) as Record<string, any>
  
  const [attackType, setAttackType] = useState('sniper')
  const [rateLimit, setRateLimit] = useState(10)
  const [positions, setPositions] = useState<PositionConfig[]>([])
  const [grepMatches, setGrepMatches] = useState<GrepMatch[]>([])
  const [extractors, setExtractors] = useState<Extractor[]>([])
  const [wordlists, setWordlists] = useState<string[]>([])
  const [attackTypes, setAttackTypes] = useState<string[]>([])
  const [processorList, setProcessorList] = useState<string[]>([])
  const [estimatedTotal, setEstimatedTotal] = useState<number | null>(null)
  const [jobId, setJobId] = useState<string | null>(null)
  const [jobStatus, setJobStatus] = useState<string | null>(null)
  const [results, setResults] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    fetchWordlists().then(setWordlists).catch(() => {})
    fetchAttackTypes().then(setAttackTypes).catch(() => {})
    fetchProcessors().then(setProcessorList).catch(() => {})
  }, [])

  useEffect(() => {
    if (!navState.url) return
    const baseReq = requests.find((r) => r.id === navState.request_id)
    if (baseReq) {
      const body = baseReq.request_body ? `\r\n${baseReq.request_body}` : ''
      setFuzzerTarget(baseReq.id, `${baseReq.method} ${baseReq.path} HTTP/1.1\r\nHost: ${baseReq.host}\r\n${body}`)
      return
    }
    let host = navState.host || ''
    let path = navState.path || ''
    try {
      const u = new URL(navState.url)
      if (!host) host = u.host
      if (!path) path = u.pathname + u.search
    } catch {}
    // Headers arrive either as an object ({Name: value}) or as pre-formatted
    // text lines ("Name: value\n...") depending on the caller (Triage sends the
    // latter). Handle both instead of silently dropping string headers.
    let headerLines: string = ''
    if (navState.headers && typeof navState.headers === 'string') {
      headerLines = navState.headers
    } else if (navState.headers && typeof navState.headers === 'object') {
      headerLines = Object.entries(navState.headers).map(([k, v]) => `${k}: ${v}`).join('\r\n')
    }
    const hdrs = headerLines ? headerLines.replace(/\r?\n/g, '\r\n') + '\r\n' : ''
    const template = `${navState.method || 'GET'} ${path} HTTP/1.1\r\nHost: ${host}\r\n${hdrs}\r\n${navState.body || ''}`
    setFuzzerTarget(navState.request_id || '', template)
  }, [])

  const extractPositionsFromTemplate = useCallback((tmpl: string): string[] => {
    const regex = /§([^§]+)§/g
    const names: string[] = []
    let m
    while ((m = regex.exec(tmpl)) !== null) {
      if (!names.includes(m[1])) names.push(m[1])
    }
    return names
  }, [])

  const updatePositions = useCallback((tmpl: string) => {
    const names = extractPositionsFromTemplate(tmpl)
    setPositions((prev) => {
      const prevMap = new Map(prev.map((p) => [p.name, p]))
      const newPositions: PositionConfig[] = names.map((name) => {
        const existing = prevMap.get(name)
        return existing || { name, wordlist_path: wordlists[0] || '', processors: [] }
      })
      return newPositions
    })
  }, [extractPositionsFromTemplate, wordlists])

  useEffect(() => {
    updatePositions(template)
  }, [template, updatePositions])

  useEffect(() => {
    if (!template || positions.length === 0 || positions.some((p) => !p.wordlist_path)) {
      setEstimatedTotal(null)
      return
    }
    const timer = setTimeout(async () => {
      try {
        const result = await previewFuzzJob({
          request_template: template,
          attack_type: attackType,
          positions: positions.map((p) => ({ name: p.name, wordlist_path: p.wordlist_path, processors: p.processors })),
        })
        setEstimatedTotal(result.total_requests)
      } catch {
        setEstimatedTotal(null)
      }
    }, 500)
    return () => clearTimeout(timer)
  }, [template, attackType, positions])

  const loadRequest = (id?: string) => {
    const targetId = id || selectedReqId
    const req = requests.find((r) => r.id === targetId)
    if (!req) return
    const body = req.request_body ? `\r\n${req.request_body}` : ''
    setFuzzerTarget(targetId, `${req.method} ${req.path} HTTP/1.1\r\nHost: ${req.host}\r\n${body}`)
  }

  const insertMarker = () => {
    const ta = textareaRef.current
    if (!ta) return
    const start = ta.selectionStart
    const end = ta.selectionEnd
    const selected = template.substring(start, end)
    const markerName = selected || 'pos'
    const before = template.substring(0, start)
    const after = template.substring(end)
    const newTemplate = `${before}§${markerName}§${after}`
    setFuzzerTarget(selectedReqId, newTemplate)
    setTimeout(() => {
      ta.focus()
      const cursorPos = start + markerName.length + 2
      ta.setSelectionRange(cursorPos, cursorPos)
    }, 0)
  }

  const runFuzz = async () => {
    if (!selectedReqId || !template || positions.length === 0) return
    setLoading(true)
    setError('')
    setResults([])
    setJobStatus('pending')
    try {
      // Prefer the session of the triaged request when the Fuzzer was opened
      // from Triage, so findings land in the same session scope the request
      // belongs to instead of whichever session happens to be active.
      const sessionId = navState.request_session_id || activeSessionId || DEFAULT_SESSION_ID
      const job = await createFuzzJob({
        session_id: sessionId,
        base_request_id: selectedReqId,
        request_template: template,
        attack_type: attackType,
        positions: positions.map((p) => ({
          name: p.name,
          wordlist_path: p.wordlist_path,
          processors: p.processors,
        })),
        grep_matches: grepMatches,
        extractors: extractors,
        rate_limit_rps: rateLimit,
      })
      setJobId(job.id)
      setJobStatus(job.status)
      storeJob('fuzzer', job.id, job.status)
      pollResults(job.id)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
      setLoading(false)
    }
  }

  const pollResults = (id: string) => {
    if (pollRef.current) clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      try {
        const job = await getFuzzJob(id)
        setJobStatus(job.status)
        if (job.results && job.results.length > 0) {
          setResults(job.results)
        }
        if (job.status === 'done' || job.status === 'cancelled') {
          if (pollRef.current) clearInterval(pollRef.current)
          setLoading(false)
          clearStoredJob('fuzzer')
        }
      } catch {
        if (pollRef.current) clearInterval(pollRef.current)
        setLoading(false)
      }
    }, 1000)
  }

  // Resume a still-running job after a tab switch: the backend job survives
  // the unmount, so re-attach to it and keep polling instead of losing it.
  useEffect(() => {
    const saved = storedJobs.fuzzer
    if (saved && saved.id) {
      setJobId(saved.id)
      setJobStatus(saved.status || 'running')
      setLoading(true)
      getFuzzJob(saved.id)
        .then((job) => {
          setJobStatus(job.status)
          if (job.results && job.results.length > 0) setResults(job.results)
          if (job.status === 'done' || job.status === 'cancelled') {
            clearStoredJob('fuzzer')
          } else {
            pollResults(saved.id)
          }
        })
        .catch(() => clearStoredJob('fuzzer'))
        .finally(() => setLoading(false))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const cancel = async () => {
    if (!jobId) return
    try {
      await cancelFuzzJob(jobId)
      setJobStatus('cancelled')
      if (pollRef.current) clearInterval(pollRef.current)
      clearStoredJob('fuzzer')
      setLoading(false)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  const addGrepMatch = () => {
    setGrepMatches((prev) => [...prev, { name: '', pattern: '', is_regex: false }])
  }

  const updateGrepMatch = (idx: number, field: keyof GrepMatch, value: any) => {
    setGrepMatches((prev) => {
      const next = [...prev]
      next[idx] = { ...next[idx], [field]: value }
      return next
    })
  }

  const removeGrepMatch = (idx: number) => {
    setGrepMatches((prev) => prev.filter((_, i) => i !== idx))
  }

  const addExtractor = () => {
    setExtractors((prev) => [...prev, { name: '', pattern: '', is_regex: false, group: 0 }])
  }

  const updateExtractor = (idx: number, field: keyof Extractor, value: any) => {
    setExtractors((prev) => {
      const next = [...prev]
      next[idx] = { ...next[idx], [field]: value }
      return next
    })
  }

  const removeExtractor = (idx: number) => {
    setExtractors((prev) => prev.filter((_, i) => i !== idx))
  }

  const updatePosition = (idx: number, field: keyof PositionConfig, value: any) => {
    setPositions((prev) => {
      const next = [...prev]
      next[idx] = { ...next[idx], [field]: value }
      return next
    })
  }

  const highlightedTemplate = template.replace(
    /§([^§]+)§/g,
    '<mark class="bg-purple-700 text-purple-200 rounded px-0.5">§$1§</mark>'
  )

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <span>Fuzzer</span>
        {jobStatus && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded ${
            jobStatus === 'running' ? 'bg-yellow-900 text-yellow-300' :
            jobStatus === 'done' ? 'bg-green-900 text-green-300' :
            jobStatus === 'cancelled' ? 'bg-red-900 text-red-300' :
            'bg-gray-800 text-gray-400'
          }`}>
            {jobStatus}
          </span>
        )}
      </div>

      <div className="flex-1 p-4 space-y-4 overflow-auto">
        {error && (
          <div className="bg-red-900/50 border border-red-800 rounded px-3 py-2 text-xs text-red-300">
            {error}
          </div>
        )}

        <div className="flex gap-2 items-start">
          <div className="flex-1">
            <label className="text-xs text-gray-500 block mb-1">Request</label>
            <ProxyRequestPicker
              value={selectedReqId}
              onChange={(req) => {
                if (!req) return
                setFuzzerTarget(req.id, template)
                loadRequest(req.id)
              }}
            />
          </div>
          <button
            className="bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded text-xs text-gray-300 mt-5"
            onClick={() => loadRequest()}
          >
            Load
          </button>
        </div>

        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="text-xs text-gray-500">Request Template</label>
            <button
              className="bg-purple-700 hover:bg-purple-600 px-2 py-0.5 rounded text-[10px] text-purple-200"
              onClick={insertMarker}
            >
              Insert §pos§
            </button>
          </div>
          <div className="relative">
            <textarea
              ref={textareaRef}
              className="w-full h-36 bg-gray-900 border border-gray-800 rounded p-2 text-xs font-mono text-transparent caret-gray-200 resize-none absolute inset-0 z-10"
              value={template}
              onChange={(e) => setFuzzerTarget(selectedReqId, e.target.value)}
              spellCheck={false}
            />
            <div
              className="w-full h-36 bg-gray-900 border border-gray-800 rounded p-2 text-xs font-mono whitespace-pre-wrap break-all overflow-auto pointer-events-none text-gray-200"
              dangerouslySetInnerHTML={{ __html: highlightedTemplate + ' ' }}
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-gray-500 block mb-1">Attack Type</label>
            <select
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
              value={attackType}
              onChange={(e) => setAttackType(e.target.value)}
            >
              {attackTypes.length > 0 ? attackTypes.map((t) => (
                <option key={t} value={t}>
                  {t === 'sniper' ? 'Sniper' :
                   t === 'batteringram' ? 'Battering ram' :
                   t === 'pitchfork' ? 'Pitchfork' :
                   t === 'clusterbomb' ? 'Cluster bomb' : t}
                </option>
              )) : (
                <>
                  <option value="sniper">Sniper</option>
                  <option value="batteringram">Battering ram</option>
                  <option value="pitchfork">Pitchfork</option>
                  <option value="clusterbomb">Cluster bomb</option>
                </>
              )}
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-500 block mb-1">Rate Limit (RPS)</label>
            <input
              type="number"
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
              value={rateLimit}
              onChange={(e) => setRateLimit(Number(e.target.value))}
              min={1}
              max={100}
            />
          </div>
        </div>

        {positions.length > 0 && (
          <div>
            <label className="text-xs text-gray-500 block mb-1">
              Position Configuration
              {estimatedTotal !== null && (
                <span className="ml-2 text-purple-400">(~{estimatedTotal} requests)</span>
              )}
            </label>
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-500 border-b border-gray-800">
                  <th className="text-left py-1 pr-2">Position</th>
                  <th className="text-left py-1 px-2">Wordlist</th>
                  <th className="text-left py-1 px-2">Processors</th>
                </tr>
              </thead>
              <tbody>
                {positions.map((pos, idx) => (
                  <tr key={pos.name} className="border-b border-gray-800/50">
                    <td className="py-1.5 pr-2 text-purple-400 font-mono">§{pos.name}§</td>
                    <td className="py-1.5 px-2">
                      <div className="space-y-1">
                        <select
                          className="w-full bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200"
                          value={pos.wordlist_path}
                          onChange={(e) => updatePosition(idx, 'wordlist_path', e.target.value)}
                        >
                          {wordlists.length === 0 && <option value="">No built-in wordlists found</option>}
                          {wordlists.map((wl) => (
                            // wl is an absolute path; show only the basename for readability
                            <option key={wl} value={wl}>{wl.split(/[\\\\/]/).pop()}</option>
                          ))}
                        </select>
                        <input
                          className="w-full bg-gray-800 border border-gray-600 rounded px-1 py-0.5 text-xs text-gray-400 placeholder:text-gray-600"
                          placeholder="Or paste absolute path: C:\\wordlists\\my.txt"
                          value={wordlists.includes(pos.wordlist_path) ? '' : pos.wordlist_path}
                          onChange={(e) => e.target.value && updatePosition(idx, 'wordlist_path', e.target.value)}
                        />
                      </div>
                    </td>
                    <td className="py-1.5 px-2">
                      <select
                        className="w-full bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-xs text-gray-200"
                        multiple
                        size={3}
                        value={pos.processors}
                        onChange={(e) => {
                          const vals = Array.from(e.target.selectedOptions, (o) => o.value)
                          updatePosition(idx, 'processors', vals)
                        }}
                      >
                        {processorList.map((p) => (
                          <option key={p} value={p}>{p}</option>
                        ))}
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="text-xs text-gray-500">Grep Match</label>
            <button className="text-purple-400 hover:text-purple-300 text-xs" onClick={addGrepMatch}>+ Add</button>
          </div>
          {grepMatches.map((gm, idx) => (
            <div key={idx} className="flex gap-2 mb-1">
              <input
                className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 w-24"
                placeholder="Name"
                value={gm.name}
                onChange={(e) => updateGrepMatch(idx, 'name', e.target.value)}
              />
              <input
                className="flex-[2] bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                placeholder="Pattern"
                value={gm.pattern}
                onChange={(e) => updateGrepMatch(idx, 'pattern', e.target.value)}
              />
              <label className="flex items-center gap-1 text-xs text-gray-500 whitespace-nowrap">
                <input
                  type="checkbox"
                  className="accent-purple-500"
                  checked={gm.is_regex}
                  onChange={(e) => updateGrepMatch(idx, 'is_regex', e.target.checked)}
                />
                Regex
              </label>
              <button className="text-red-500 hover:text-red-400 text-xs" onClick={() => removeGrepMatch(idx)}>✕</button>
            </div>
          ))}
        </div>

        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="text-xs text-gray-500">Response Extraction</label>
            <button className="text-purple-400 hover:text-purple-300 text-xs" onClick={addExtractor}>+ Add</button>
          </div>
          {extractors.map((ext, idx) => (
            <div key={idx} className="flex gap-2 mb-1">
              <input
                className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 w-24"
                placeholder="Name"
                value={ext.name}
                onChange={(e) => updateExtractor(idx, 'name', e.target.value)}
              />
              <input
                className="flex-[2] bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                placeholder="Pattern"
                value={ext.pattern}
                onChange={(e) => updateExtractor(idx, 'pattern', e.target.value)}
              />
              <label className="flex items-center gap-1 text-xs text-gray-500 whitespace-nowrap">
                <input
                  type="checkbox"
                  className="accent-purple-500"
                  checked={ext.is_regex}
                  onChange={(e) => updateExtractor(idx, 'is_regex', e.target.checked)}
                />
                Regex
              </label>
              <input
                type="number"
                className="w-12 bg-gray-800 border border-gray-700 rounded px-1 py-1 text-xs text-gray-200"
                placeholder="Grp"
                value={ext.group}
                onChange={(e) => updateExtractor(idx, 'group', Number(e.target.value))}
                min={0}
              />
              <button className="text-red-500 hover:text-red-400 text-xs" onClick={() => removeExtractor(idx)}>✕</button>
            </div>
          ))}
        </div>

        <div className="flex gap-2 items-center pt-2 border-t border-gray-800">
          <button
            className="bg-purple-600 hover:bg-purple-700 px-4 py-1.5 rounded text-xs font-medium disabled:opacity-50"
            onClick={runFuzz}
            disabled={loading || !template || positions.length === 0 || positions.some((p) => !p.wordlist_path)}
          >
            {loading ? 'Fuzzing...' : 'Start Fuzz'}
          </button>
          {jobId && (
            <button
              className="bg-red-700 hover:bg-red-600 px-3 py-1.5 rounded text-xs font-medium disabled:opacity-50"
              onClick={cancel}
              disabled={!loading && jobStatus !== 'running'}
            >
              Cancel
            </button>
          )}
          {estimatedTotal !== null && !loading && (
            <span className="text-xs text-gray-500 ml-auto">
              Estimated: {estimatedTotal.toLocaleString()} requests
            </span>
          )}
          {results.length > 0 && (
            <span className="text-xs text-gray-500">
              {results.length} results loaded
            </span>
          )}
        </div>

        {(results.length > 0 || loading) && (
          <div className="border border-gray-800 rounded">
            <div className="px-3 py-2 border-b border-gray-800 text-xs text-gray-400 font-medium">
              Results
            </div>
            <div className="p-3">
              <FuzzResults
                results={results}
                grepMatchNames={grepMatches.filter((g) => g.name).map((g) => g.name)}
                extractorNames={extractors.filter((e) => e.name).map((e) => e.name)}
                loading={loading && results.length === 0}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

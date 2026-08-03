import { useState, useEffect, useCallback, useRef } from 'react'
import { Globe, Play, XCircle, Settings, List, FileText, ChevronDown, ChevronRight, Plus, Trash2 } from 'lucide-react'
import { apiClient } from '../../api/client'
import { startCrawl, stopCrawl, listCrawlJobs, getCrawlStatus, type CrawlJob } from '../../api/endpoints/crawler'
import { useJobsStore } from '../../store/useJobsStore'

function KeyValueEditor({ pairs, onChange, keyPlaceholder, valuePlaceholder }: {
  pairs: [string, string][]
  onChange: (pairs: [string, string][]) => void
  keyPlaceholder?: string
  valuePlaceholder?: string
}) {
  const update = (i: number, k: string, v: string) => {
    const next = [...pairs]
    next[i] = [k, v]
    onChange(next)
  }
  const remove = (i: number) => {
    onChange(pairs.filter((_, idx) => idx !== i))
  }
  const add = () => {
    onChange([...pairs, ['', '']])
  }

  return (
    <div className="space-y-1">
      {(pairs || []).map(([k, v], i) => (
        <div key={i} className="flex gap-1">
          <input
            className="flex-1 bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-200 w-24"
            placeholder={keyPlaceholder || 'key'}
            value={k}
            onChange={(e) => update(i, e.target.value, v)}
          />
          <input
            className="flex-1 bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-200 w-24"
            placeholder={valuePlaceholder || 'value'}
            value={v}
            onChange={(e) => update(i, k, e.target.value)}
          />
          <button className="text-red-400 hover:text-red-300" onClick={() => remove(i)}>
            <Trash2 size={12} />
          </button>
        </div>
      ))}
      <button
        className="flex items-center gap-1 text-xs text-purple-400 hover:text-purple-300"
        onClick={add}
      >
        <Plus size={12} /> Add
      </button>
    </div>
  )
}

function TagsInput({ tags, onChange, placeholder }: {
  tags: string[]
  onChange: (tags: string[]) => void
  placeholder?: string
}) {
  const [value, setValue] = useState('')
  const addTag = () => {
    const trimmed = value.trim()
    if (trimmed && !tags.includes(trimmed)) {
      onChange([...tags, trimmed])
    }
    setValue('')
  }
  return (
    <div>
      <div className="flex gap-1 mb-1">
        <input
          className="flex-1 bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-200"
          placeholder={placeholder || 'pattern'}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addTag() } }}
        />
        <button className="text-xs text-purple-400 hover:text-purple-300" onClick={addTag}>Add</button>
      </div>
      <div className="flex flex-wrap gap-1">
        {(tags || []).map((t, i) => (
          <span key={i} className="inline-flex items-center gap-1 bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded text-xs">
            {t}
            <button className="text-gray-500 hover:text-red-400" onClick={() => onChange(tags.filter((_, idx) => idx !== i))}>
              <XCircle size={10} />
            </button>
          </span>
        ))}
      </div>
    </div>
  )
}

function LoginMacroEditor({ steps, onChange }: {
  steps: { url: string; method: string; body: string; headers: [string, string][] }[]
  onChange: (steps: any[]) => void
}) {
  const update = (i: number, field: string, value: any) => {
    const next = [...steps]
    next[i] = { ...next[i], [field]: value }
    onChange(next)
  }
  const updateHeaders = (i: number, headers: [string, string][]) => {
    const next = [...steps]
    next[i] = { ...next[i], headers }
    onChange(next)
  }
  const remove = (i: number) => {
    onChange(steps.filter((_, idx) => idx !== i))
  }
  const add = () => {
    onChange([...steps, { url: '', method: 'GET', body: '', headers: [] }])
  }

  return (
    <div className="space-y-2">
      {(steps || []).map((step, i) => (
        <div key={i} className="bg-gray-800 border border-gray-700 rounded p-2 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400">Step {i + 1}</span>
            <button className="text-red-400 hover:text-red-300" onClick={() => remove(i)}>
              <Trash2 size={12} />
            </button>
          </div>
          <div className="flex gap-1">
            <select
              className="bg-gray-700 border border-gray-600 rounded px-1 py-0.5 text-xs text-gray-200 w-16"
              value={step.method}
              onChange={(e) => update(i, 'method', e.target.value)}
            >
              <option>GET</option>
              <option>POST</option>
              <option>PUT</option>
              <option>DELETE</option>
            </select>
            <input
              className="flex-1 bg-gray-700 border border-gray-600 rounded px-1.5 py-0.5 text-xs text-gray-200"
              placeholder="https://target.com/login"
              value={step.url}
              onChange={(e) => update(i, 'url', e.target.value)}
            />
          </div>
          {step.method !== 'GET' && (
            <textarea
              className="w-full bg-gray-700 border border-gray-600 rounded px-1.5 py-0.5 text-xs text-gray-200 font-mono"
              placeholder="username=admin&password=pass"
              rows={2}
              value={step.body}
              onChange={(e) => update(i, 'body', e.target.value)}
            />
          )}
          <details className="text-xs">
            <summary className="text-gray-500 cursor-pointer">Headers</summary>
            <div className="mt-1">
              <KeyValueEditor
                pairs={step.headers}
                onChange={(pairs) => updateHeaders(i, pairs)}
                keyPlaceholder="header"
                valuePlaceholder="value"
              />
            </div>
          </details>
        </div>
      ))}
      <button
        className="flex items-center gap-1 text-xs text-purple-400 hover:text-purple-300"
        onClick={add}
      >
        <Plus size={12} /> Add Step
      </button>
    </div>
  )
}

export function Crawler() {
  const { jobs: storedJobs, setJob: storeJob, clearJob: clearStoredJob } = useJobsStore()
  const [startUrl, setStartUrl] = useState('')
  const [maxDepth, setMaxDepth] = useState(3)
  const [maxPages, setMaxPages] = useState(50)
  const [scopeInclude, setScopeInclude] = useState<string[]>([])
  const [scopeExclude, setScopeExclude] = useState<string[]>([])
  const [formFillConfig, setFormFillConfig] = useState<[string, string][]>([
    ['email', 'test@example.com'],
    ['password', 'Passw0rd!'],
    ['name', 'John Doe'],
  ])
  const [loginMacro, setLoginMacro] = useState<{ url: string; method: string; body: string; headers: [string, string][] }[]>([])
  const [customHeaders, setCustomHeaders] = useState<[string, string][]>([])
  const [respectRobotsTxt, setRespectRobotsTxt] = useState(true)
  const [showConfig, setShowConfig] = useState(false)

  const [currentJobId, setCurrentJobId] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [status, setStatus] = useState<string | null>(null)
  const [progress, setProgress] = useState(0)
  const [discovered, setDiscovered] = useState<string[]>([])
  const [forms, setForms] = useState<any[]>([])
  const [jobs, setJobs] = useState<CrawlJob[]>([])
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null)

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const startTimeRef = useRef<number>(0)

  const startCrawlHandler = async () => {
    if (!startUrl) return
    setLoading(true)
    setError('')
    setStatus('Starting crawl...')
    setProgress(0)
    setDiscovered([])
    setForms([])
    startTimeRef.current = Date.now()

    const formFillObj: Record<string, string> = {}
    formFillConfig.forEach(([k, v]) => { if (k) formFillObj[k] = v })

    const headersObj: Record<string, string> = {}
    customHeaders.forEach(([k, v]) => { if (k) headersObj[k] = v })

    try {
      const job = await startCrawl({
        start_url: startUrl,
        max_depth: maxDepth,
        max_pages: maxPages,
        scope_include: scopeInclude,
        scope_exclude: scopeExclude,
        form_fill_config: formFillObj,
        login_macro: (loginMacro || []).map((s) => {
          const h: Record<string, string> = {}
          s.headers.forEach(([k, v]) => { if (k) h[k] = v })
          return { url: s.url, method: s.method, body: s.body || undefined, headers: h }
        }),
        headers: headersObj,
        respect_robots_txt: respectRobotsTxt,
      })
      setCurrentJobId(job.id)
      setSelectedJobId(job.id)
      storeJob('crawler', job.id, 'running')
      setStatus('Running...')
      refreshJobs()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
      setStatus('Error')
      setLoading(false)
    }
  }

  const stopCrawlHandler = async () => {
    if (!currentJobId) return
    try {
      await stopCrawl(currentJobId)
      setStatus('Stopped')
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const refreshJobs = useCallback(async () => {
    try {
      const jobList = await listCrawlJobs()
      setJobs(jobList)
      if (selectedJobId) {
        const active = jobList.find((j) => j.id === selectedJobId)
        if (active) {
          setDiscovered(active.discovered_urls || [])
          setProgress(active.progress)
          setStatus(active.status)
          if (active.status === 'completed' || active.status === 'stopped' || active.status === 'failed') {
            setLoading(false)
            clearStoredJob('crawler')
            if (pollRef.current) {
              clearInterval(pollRef.current)
              pollRef.current = null
            }
          }
        }
      }
    } catch {
      // ignore poll errors
    }
  }, [selectedJobId])

  useEffect(() => {
    if (currentJobId && loading) {
      pollRef.current = setInterval(refreshJobs, 2000)
      return () => {
        if (pollRef.current) {
          clearInterval(pollRef.current)
          pollRef.current = null
        }
      }
    }
  }, [currentJobId, loading, refreshJobs])

  useEffect(() => {
    refreshJobs()
  }, [refreshJobs])

  // Resume a still-running crawl after a tab switch.
  useEffect(() => {
    const saved = storedJobs.crawler
    if (saved && saved.id) {
      setCurrentJobId(saved.id)
      setSelectedJobId(saved.id)
      setLoading(true)
      refreshJobs()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const viewJob = async (jobId: string) => {
    setSelectedJobId(jobId)
    try {
      const job = await getCrawlStatus(jobId)
      setDiscovered(job.discovered_urls || [])
      setProgress(job.progress)
      setStatus(job.status)
    } catch {
      // ignore
    }
  }

  const elapsed = startTimeRef.current && progress > 0
    ? ((Date.now() - startTimeRef.current) / 1000).toFixed(1)
    : '0.0'
  const pagesPerSec = progress > 0 && parseFloat(elapsed) > 0
    ? (progress / parseFloat(elapsed)).toFixed(1)
    : '0.0'

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <Globe size={14} className="text-purple-400" />
        Crawler
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Left panel - controls */}
        <div className="w-1/2 border-r border-gray-800 flex flex-col overflow-hidden">
          <div className="p-3 space-y-3 overflow-auto flex-1">
            <div>
              <label className="text-xs text-gray-500 block mb-1">Target URL</label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200 font-mono"
                placeholder="https://target.com/"
                value={startUrl}
                onChange={(e) => setStartUrl(e.target.value)}
              />
            </div>

            <div className="flex gap-2">
              <button
                className="flex items-center gap-1.5 bg-purple-600 hover:bg-purple-700 px-3 py-1.5 rounded text-xs font-medium disabled:opacity-50"
                onClick={startCrawlHandler}
                disabled={loading || !startUrl}
              >
                <Play size={12} /> {loading ? 'Running...' : 'Start Crawl'}
              </button>
              {currentJobId && loading && (
                <button
                  className="flex items-center gap-1.5 bg-red-600 hover:bg-red-700 px-3 py-1.5 rounded text-xs font-medium"
                  onClick={stopCrawlHandler}
                >
                  <XCircle size={12} /> Stop
                </button>
              )}
            </div>

            {error && <div className="text-red-400 text-xs bg-red-900/20 border border-red-800 rounded p-2">{error}</div>}

            {/* Config section */}
            <div>
              <button
                className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-200"
                onClick={() => setShowConfig(!showConfig)}
              >
                <Settings size={12} />
                Configuration
                {showConfig ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              </button>
              {showConfig && (
                <div className="mt-2 space-y-3 pl-4 border-l border-gray-800">
                  <div className="flex gap-4">
                    <div>
                      <label className="text-xs text-gray-500 block mb-1">Max Depth</label>
                      <input
                        type="number"
                        className="w-20 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                        value={maxDepth}
                        onChange={(e) => setMaxDepth(Number(e.target.value))}
                        min={1}
                        max={10}
                      />
                    </div>
                    <div>
                      <label className="text-xs text-gray-500 block mb-1">Max Pages</label>
                      <input
                        type="number"
                        className="w-20 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                        value={maxPages}
                        onChange={(e) => setMaxPages(Number(e.target.value))}
                        min={1}
                        max={1000}
                      />
                    </div>
                  </div>

                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Scope Include</label>
                    <TagsInput tags={scopeInclude} onChange={setScopeInclude} placeholder="/api/ , /admin/" />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Scope Exclude</label>
                    <TagsInput tags={scopeExclude} onChange={setScopeExclude} placeholder="/logout , /cdn/" />
                  </div>

                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Form Auto-Fill (field_type/name → value)</label>
                    <KeyValueEditor
                      pairs={formFillConfig}
                      onChange={setFormFillConfig}
                      keyPlaceholder="field name/type"
                      valuePlaceholder="fill value"
                    />
                  </div>

                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Custom Headers</label>
                    <KeyValueEditor
                      pairs={customHeaders}
                      onChange={setCustomHeaders}
                      keyPlaceholder="header"
                      valuePlaceholder="value"
                    />
                  </div>

                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Login Macro</label>
                    <LoginMacroEditor steps={loginMacro} onChange={setLoginMacro} />
                  </div>

                  <label className="flex items-center gap-2 text-xs text-gray-400">
                    <input
                      type="checkbox"
                      checked={respectRobotsTxt}
                      onChange={(e) => setRespectRobotsTxt(e.target.checked)}
                      className="accent-purple-500"
                    />
                    Respect robots.txt
                  </label>
                </div>
              )}
            </div>

            {/* Status */}
            {status && (
              <div className="bg-gray-900 border border-gray-800 rounded p-3 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-400">Status:</span>
                  <span className={status === 'running' ? 'text-green-400' : 'text-gray-300'}>{status}</span>
                </div>
                {currentJobId && (
                  <>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-gray-400">Progress:</span>
                      <span className="text-gray-300">{progress} / {maxPages}</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-1.5">
                      <div
                        className="bg-purple-600 h-1.5 rounded-full transition-all"
                        style={{ width: `${Math.min((progress / maxPages) * 100, 100)}%` }}
                      />
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-gray-400">Speed:</span>
                      <span className="text-gray-300">{pagesPerSec} pages/sec</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-gray-400">Elapsed:</span>
                      <span className="text-gray-300">{elapsed}s</span>
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right panel - results */}
        <div className="w-1/2 flex flex-col overflow-hidden">
          {/* Tabs */}
          <div className="flex border-b border-gray-800 text-xs">
            <button
              className={`flex items-center gap-1 px-3 py-2 border-b-2 ${selectedJobId ? 'border-purple-500 text-gray-200' : 'border-transparent text-gray-500'}`}
              onClick={() => setSelectedJobId(currentJobId)}
            >
              <Globe size={12} /> URLs
            </button>
            <button
              className={`flex items-center gap-1 px-3 py-2 border-b-2 ${!selectedJobId ? 'border-purple-500 text-gray-200' : 'border-transparent text-gray-500'}`}
              onClick={() => setSelectedJobId(null)}
            >
              <List size={12} /> Jobs
            </button>
          </div>

          <div className="flex-1 overflow-auto p-3 space-y-3">
            {selectedJobId ? (
              <>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-400">
                    <FileText size={12} className="inline mr-1" />
                    Discovered URLs ({discovered.length})
                  </span>
                  <span className="text-xs text-gray-500">Forms: {forms.length}</span>
                </div>
                <div className="bg-gray-900 border border-gray-800 rounded p-2 max-h-60 overflow-auto">
                  {discovered.length === 0 && <div className="text-xs text-gray-600 italic">No URLs discovered yet</div>}
                  {(discovered || []).map((url, i) => (
                    <div key={i} className="text-xs text-gray-400 font-mono truncate py-0.5 hover:text-gray-200 cursor-pointer" title={url}>
                      {url}
                    </div>
                  ))}
                </div>

                {forms.length > 0 && (
                  <div>
                    <span className="text-xs text-gray-400 block mb-1">
                      <FileText size={12} className="inline mr-1" />
                      Discovered Forms ({forms.length})
                    </span>
                    <div className="bg-gray-900 border border-gray-800 rounded p-2 max-h-40 overflow-auto space-y-2">
                      {(forms || []).map((f, i) => (
                        <div key={i} className="border-b border-gray-800 pb-1 last:border-0">
                          <div className="text-xs text-gray-500 font-mono truncate">{f.page_url || 'unknown'}</div>
                          <div className="text-xs text-gray-400">
                            {f.method || 'GET'} → {f.action || '(same page)'} — {f.inputs?.length || 0} fields
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              /* Jobs list */
              <div>
                <span className="text-xs text-gray-400 block mb-2">
                  <List size={12} className="inline mr-1" />
                  Crawl Jobs
                </span>
                {jobs.length === 0 && <div className="text-xs text-gray-600 italic">No crawl jobs yet</div>}
                <div className="space-y-1">
                  {(jobs || []).map((job) => (
                    <div
                      key={job.id}
                      className="flex items-center justify-between bg-gray-900 border border-gray-800 rounded p-2 cursor-pointer hover:bg-gray-800"
                      onClick={() => viewJob(job.id)}
                    >
                      <div className="flex-1 min-w-0">
                        <div className="text-xs text-gray-300 font-mono truncate">{job.start_url}</div>
                        <div className="text-xs text-gray-500">
                          {job.status} · {job.progress}/{job.max_pages} pages · {job.discovered_urls?.length || 0} URLs
                          {job.created_at && ` · ${new Date(job.created_at).toLocaleTimeString()}`}
                        </div>
                      </div>
                      {job.status === 'running' && (
                        <button
                          className="text-red-400 hover:text-red-300 ml-2"
                          onClick={(e) => { e.stopPropagation(); stopCrawl(job.id).then(refreshJobs) }}
                        >
                          <XCircle size={14} />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

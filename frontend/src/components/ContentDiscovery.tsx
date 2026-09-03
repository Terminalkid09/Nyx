import { useState, useEffect, useRef } from 'react'
import { apiClient } from '../api/client'
import { useJobsStore } from '../store/useJobsStore'

interface DiscoveredItem {
  url: string
  path: string
  method: string
  status_code: number
  size: number
  time_ms: number
}

interface JobStatus {
  job_id: string
  target_url: string
  discovered: DiscoveredItem[]
  total: number
  completed: number
  status: string
}

interface DiscoveryJob {
  job_id: string
  target_url: string
  status: string
  total: number
  completed: number
  discovered_count: number
  created_at: string
}

export function ContentDiscovery() {
  const { jobs: storedJobs, setJob: storeJob, clearJob: clearStoredJob } = useJobsStore()
  const [targetUrl, setTargetUrl] = useState('')
  const [wordlist, setWordlist] = useState('')
  const [wordlists, setWordlists] = useState<string[]>([])
  const [extensions, setExtensions] = useState('.php,.asp,.jsp,.aspx,.txt,.bak,.zip,.tar.gz,.git')
  const [methods, setMethods] = useState<string[]>(['GET'])
  const [throttle, setThrottle] = useState(0)
  const [discovering, setDiscovering] = useState(false)
  const [results, setResults] = useState<DiscoveredItem[]>([])
  const [status, setStatus] = useState<string | null>(null)
  const [jobId, setJobId] = useState<string | null>(null)
  const [jobs, setJobs] = useState<DiscoveryJob[]>([])
  const [progress, setProgress] = useState({ completed: 0, total: 0 })
  const [error, setError] = useState('')
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    apiClient.get('/api/content-discovery/wordlists').then(({ data }) => setWordlists(data)).catch(() => {})
    apiClient.get('/api/content-discovery/jobs').then(({ data }) => setJobs(data)).catch(() => {})
  }, [])

  const toggleMethod = (m: string) => {
    setMethods((prev) =>
      prev.includes(m) ? prev.filter((x) => x !== m) : [...prev, m]
    )
  }

  const startDiscovery = async () => {
    if (!targetUrl || !wordlist) return
    setError('')
    setDiscovering(true)
    setResults([])
    setStatus('pending')
    setProgress({ completed: 0, total: 0 })

    const extList = extensions
      .split(',')
      .map((e) => e.trim())
      .filter((e) => e.length > 0)
    if (extList.length === 0) extList.push('')

    try {
      const { data } = await apiClient.post('/api/content-discovery/start', {
        target_url: targetUrl,
        wordlist_path: wordlist,
        extensions: extList,
        methods,
        throttle_ms: throttle,
      })
      setJobId(data.job_id)
      storeJob('content-discovery', data.job_id, 'pending')
      pollResults(data.job_id)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to start discovery')
      setDiscovering(false)
    }
  }

  const pollResults = (id: string) => {
    if (pollRef.current) clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      try {
        const { data } = await apiClient.get<JobStatus>(`/api/content-discovery/status/${id}`)
        setStatus(data.status)
        setProgress({ completed: data.completed, total: data.total })
        if (data.discovered && data.discovered.length > 0) {
          setResults(data.discovered)
        }
        if (data.status === 'done' || data.status === 'cancelled' || data.status === 'error') {
          if (pollRef.current) clearInterval(pollRef.current)
          setDiscovering(false)
          clearStoredJob('content-discovery')
          setJobs([])
          apiClient.get('/api/content-discovery/jobs').then(({ data }) => setJobs(data)).catch(() => {})
        }
      } catch {
        if (pollRef.current) clearInterval(pollRef.current)
        setDiscovering(false)
      }
    }, 2000)
  }

  // Resume a still-running job after a tab switch.
  useEffect(() => {
    const saved = storedJobs['content-discovery']
    if (saved && saved.id) {
      setJobId(saved.id)
      setDiscovering(true)
      apiClient
        .get<JobStatus>(`/api/content-discovery/status/${saved.id}`)
        .then(({ data }) => {
          setStatus(data.status)
          setProgress({ completed: data.completed, total: data.total })
          if (data.discovered && data.discovered.length > 0) setResults(data.discovered)
          if (data.status === 'done' || data.status === 'cancelled' || data.status === 'error') {
            clearStoredJob('content-discovery')
            setDiscovering(false)
          } else {
            pollResults(saved.id)
          }
        })
        .catch(() => clearStoredJob('content-discovery'))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const stopDiscovery = async () => {
    if (!jobId) return
    try {
      await apiClient.post(`/api/content-discovery/stop/${jobId}`)
      setStatus('cancelled')
      if (pollRef.current) clearInterval(pollRef.current)
      clearStoredJob('content-discovery')
      setDiscovering(false)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to stop')
    }
  }

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  const progressPct = progress.total > 0 ? Math.round((progress.completed / progress.total) * 100) : 0

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <span>Content Discovery</span>
        {status && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded ${
            status === 'running' ? 'bg-yellow-900 text-yellow-300' :
            status === 'done' ? 'bg-green-900 text-green-300' :
            status === 'cancelled' ? 'bg-red-900 text-red-300' :
            'bg-gray-800 text-gray-400'
          }`}>
            {status}
          </span>
        )}
      </div>

      <div className="flex-1 p-4 space-y-4 overflow-auto">
        {error && (
          <div className="bg-red-900/50 border border-red-800 rounded px-3 py-2 text-xs text-red-300">
            {error}
          </div>
        )}

        <div>
          <label className="text-xs text-gray-500 block mb-1">Target URL</label>
          <input
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
            placeholder="https://example.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>

        <div>
          <label className="text-xs text-gray-500 block mb-1">Wordlist</label>
          <select
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
            value={wordlists.includes(wordlist) ? wordlist : ''}
            onChange={(e) => { if (e.target.value) setWordlist(e.target.value) }}
          >
            <option value="">Select wordlist...</option>
            {wordlists.map((wl) => (
              <option key={wl} value={wl}>{wl.split(/[\\\\/]/).pop()}</option>
            ))}
          </select>
          <input
            className="w-full bg-gray-800 border border-gray-600 rounded px-2 py-1 mt-1 text-xs text-gray-400 placeholder:text-gray-600"
            placeholder="Or paste absolute path: C:\\path\\to\\wordlist.txt"
            value={wordlists.includes(wordlist) ? '' : wordlist}
            onChange={(e) => e.target.value && setWordlist(e.target.value)}
          />
        </div>

        <div>
          <label className="text-xs text-gray-500 block mb-1">Extensions (comma separated)</label>
          <input
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
            placeholder=".php,.asp,.jsp"
            value={extensions}
            onChange={(e) => setExtensions(e.target.value)}
          />
        </div>

        <div>
          <label className="text-xs text-gray-500 block mb-1">Methods</label>
          <div className="flex gap-3">
            {['GET', 'HEAD', 'POST'].map((m) => (
              <label key={m} className="flex items-center gap-1 text-xs text-gray-300">
                <input
                  type="checkbox"
                  className="accent-purple-500"
                  checked={methods.includes(m)}
                  onChange={() => toggleMethod(m)}
                />
                {m}
              </label>
            ))}
          </div>
        </div>

        <div>
          <label className="text-xs text-gray-500 block mb-1">Throttle (ms between requests)</label>
          <input
            type="number"
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
            value={throttle}
            onChange={(e) => setThrottle(Number(e.target.value))}
            min={0}
            max={10000}
          />
        </div>

        <div className="flex gap-2 items-center pt-2 border-t border-gray-800">
          <button
            className="bg-purple-600 hover:bg-purple-700 px-4 py-1.5 rounded text-xs font-medium disabled:opacity-50"
            onClick={startDiscovery}
            disabled={discovering || !targetUrl || !wordlist}
          >
            {discovering ? 'Discovering...' : 'Start Discovery'}
          </button>
          {jobId && (
            <button
              className="bg-red-700 hover:bg-red-600 px-3 py-1.5 rounded text-xs font-medium disabled:opacity-50"
              onClick={stopDiscovery}
              disabled={!discovering}
            >
              Stop
            </button>
          )}
        </div>

        {discovering && progress.total > 0 && (
          <div>
            <div className="flex justify-between text-xs text-gray-400 mb-1">
              <span>Progress: {progress.completed} / {progress.total}</span>
              <span>{progressPct}%</span>
            </div>
            <div className="w-full bg-gray-800 rounded h-2">
              <div
                className="bg-purple-600 h-2 rounded transition-all duration-300"
                style={{ width: `${progressPct}%` }}
              />
            </div>
          </div>
        )}

        {results.length > 0 && (
          <div className="border border-gray-800 rounded overflow-hidden">
            <div className="px-3 py-2 border-b border-gray-800 text-xs text-gray-400 font-medium flex justify-between">
              <span>Discovered Items ({results.length})</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500 border-b border-gray-800">
                    <th className="text-left py-2 px-3">Path</th>
                    <th className="text-left py-2 px-3">Method</th>
                    <th className="text-left py-2 px-3">Status</th>
                    <th className="text-right py-2 px-3">Size</th>
                    <th className="text-right py-2 px-3">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((item, idx) => (
                    <tr
                      key={idx}
                      className={`border-b border-gray-800/50 hover:bg-gray-800/30 ${
                        item.status_code >= 200 && item.status_code < 300
                          ? 'text-green-400'
                          : item.status_code >= 300 && item.status_code < 400
                          ? 'text-yellow-400'
                          : item.status_code >= 400 && item.status_code < 500
                          ? 'text-orange-400'
                          : item.status_code >= 500
                          ? 'text-red-400'
                          : 'text-gray-400'
                      }`}
                    >
                      <td className="py-1.5 px-3 font-mono">{item.path}</td>
                      <td className="py-1.5 px-3">{item.method}</td>
                      <td className="py-1.5 px-3 font-mono">{item.status_code}</td>
                      <td className="py-1.5 px-3 text-right font-mono">{item.size.toLocaleString()}</td>
                      <td className="py-1.5 px-3 text-right font-mono">{item.time_ms}ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {jobs.length > 0 && !discovering && (
          <div className="border border-gray-800 rounded overflow-hidden">
            <div className="px-3 py-2 border-b border-gray-800 text-xs text-gray-400 font-medium">
              Previous Jobs
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500 border-b border-gray-800">
                    <th className="text-left py-2 px-3">Target</th>
                    <th className="text-left py-2 px-3">Status</th>
                    <th className="text-right py-2 px-3">Found</th>
                    <th className="text-right py-2 px-3">Requests</th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.map((j) => (
                    <tr key={j.job_id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                      <td className="py-1.5 px-3 font-mono">{j.target_url}</td>
                      <td className="py-1.5 px-3">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                          j.status === 'done' ? 'bg-green-900 text-green-300' :
                          j.status === 'cancelled' ? 'bg-red-900 text-red-300' :
                          j.status === 'running' ? 'bg-yellow-900 text-yellow-300' :
                          'bg-gray-800 text-gray-400'
                        }`}>
                          {j.status}
                        </span>
                      </td>
                      <td className="py-1.5 px-3 text-right">{j.discovered_count}</td>
                      <td className="py-1.5 px-3 text-right">{j.completed}/{j.total}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

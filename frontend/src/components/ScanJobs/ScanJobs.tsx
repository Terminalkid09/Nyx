import { useState, useEffect, useRef } from 'react'
import { Play, XCircle, RefreshCw, Plus, ArrowUp, ArrowDown, Layers } from 'lucide-react'
import {
  fetchScanJobs,
  createScanJob,
  startScanJob,
  cancelScanJob,
} from '../../api/endpoints/scanJobs'
import { ScanJob } from '../../types'

const PRIORITY_LABELS: Record<number, string> = {
  1: 'Lowest', 2: 'Low', 3: 'Low-Mid', 4: 'Medium-Low',
  5: 'Medium', 6: 'Medium-High', 7: 'High',
  8: 'Very High', 9: 'Critical', 10: 'Emergency',
}

const PRIORITY_COLORS: Record<number, string> = {
  1: 'bg-gray-500', 2: 'bg-gray-500', 3: 'bg-blue-500',
  4: 'bg-blue-500', 5: 'bg-green-500', 6: 'bg-green-500',
  7: 'bg-yellow-500', 8: 'bg-orange-500', 9: 'bg-red-500', 10: 'bg-red-500',
}

const STATUS_COLORS: Record<string, string> = {
  pending: 'bg-yellow-500/20 text-yellow-400',
  running: 'bg-blue-500/20 text-blue-400',
  completed: 'bg-green-500/20 text-green-400',
  failed: 'bg-red-500/20 text-red-400',
  cancelled: 'bg-gray-500/20 text-gray-400',
}

export function ScanJobs() {
  const [jobs, setJobs] = useState<ScanJob[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showNewForm, setShowNewForm] = useState(false)
  const [newJob, setNewJob] = useState({
    scan_type: 'active',
    target_url: '',
    priority: 5,
    config: '{}',
  })
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [viewMode, setViewMode] = useState<'all' | 'queue'>('all')
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const loadJobs = () => {
    const fetcher = viewMode === 'queue'
      ? fetch('/api/scan-jobs/queue').then(r => r.json())
      : fetchScanJobs()
    fetcher
      .then(setJobs)
      .catch((err: any) => setError(err.response?.data?.detail || err.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadJobs()
    return () => { if (pollingRef.current) clearInterval(pollingRef.current) }
  }, [viewMode])

  const anyRunning = jobs.some((j) => j.status === 'running' || j.status === 'pending')
  useEffect(() => {
    if (anyRunning && !pollingRef.current) {
      pollingRef.current = setInterval(() => {
        const fetcher = viewMode === 'queue'
          ? fetch('/api/scan-jobs/queue').then(r => r.json())
          : fetchScanJobs()
        fetcher.then(setJobs).catch(() => {})
      }, 5000)
    } else if (!anyRunning && pollingRef.current) {
      clearInterval(pollingRef.current)
      pollingRef.current = null
    }
    return () => { if (pollingRef.current) clearInterval(pollingRef.current) }
  }, [anyRunning, viewMode])

  const handleCreate = async () => {
    try {
      const config = { ...JSON.parse(newJob.config || '{}'), priority: newJob.priority }
      await createScanJob({
        session_id: '00000000-0000-0000-0000-000000000001',
        scan_type: newJob.scan_type,
        target_url: newJob.target_url || undefined,
        config,
      })
      setShowNewForm(false)
      setNewJob({ scan_type: 'active', target_url: '', priority: 5, config: '{}' })
      loadJobs()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleStart = async (id: string) => {
    setActionLoading(id)
    try { await startScanJob(id); loadJobs() }
    catch (err: any) { setError(err.response?.data?.detail || err.message) }
    finally { setActionLoading(null) }
  }

  const handleCancel = async (id: string) => {
    setActionLoading(id)
    try { await cancelScanJob(id); loadJobs() }
    catch (err: any) { setError(err.response?.data?.detail || err.message) }
    finally { setActionLoading(null) }
  }

  const handlePriorityChange = async (id: string, delta: number) => {
    const job = jobs.find(j => j.id === id)
    if (!job) return
    const newP = Math.max(1, Math.min(10, (job as any).priority + delta))
    try {
      await fetch(`/api/scan-jobs/${id}/priority?priority=${newP}`, { method: 'POST' })
      loadJobs()
    } catch (err: any) {
      setError(err.message)
    }
  }

  const activeQueue = jobs.filter(j => j.status === 'pending' || j.status === 'running')
  const completedJobs = jobs.filter(j => j.status === 'completed' || j.status === 'failed' || j.status === 'cancelled')

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Layers size={16} className="text-purple-500" />
          <span>Scan Jobs</span>
          {activeQueue.length > 0 && (
            <span className="text-[10px] text-purple-400 animate-pulse ml-2">
              {activeQueue.length} active
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <div className="flex bg-gray-800 rounded overflow-hidden text-xs">
            <button
              className={`px-2 py-1 ${viewMode === 'all' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-gray-300'}`}
              onClick={() => setViewMode('all')}
            >All</button>
            <button
              className={`px-2 py-1 ${viewMode === 'queue' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-gray-300'}`}
              onClick={() => setViewMode('queue')}
            >Queue</button>
          </div>
          <button onClick={loadJobs} className="p-1 text-gray-500 hover:text-gray-300"><RefreshCw size={12} /></button>
          <button onClick={() => setShowNewForm(true)} className="flex items-center gap-1 bg-purple-600 hover:bg-purple-700 px-2 py-1 rounded text-xs font-medium">
            <Plus size={12} /> New
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-3">
        {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>}

        {showNewForm && (
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 space-y-3">
            <div className="text-xs font-medium text-gray-400">New Scan Job</div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">Target URL</label>
                <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
                  value={newJob.target_url} onChange={e => setNewJob(j => ({ ...j, target_url: e.target.value }))} />
              </div>
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">Scan Type</label>
                <select className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                  value={newJob.scan_type} onChange={e => setNewJob(j => ({ ...j, scan_type: e.target.value }))}>
                  <option value="active">Active Scan</option>
                  <option value="passive">Passive Only</option>
                  <option value="full">Full Scan</option>
                  <option value="discovery">Content Discovery</option>
                </select>
              </div>
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">Priority (1-10)</label>
                <input type="range" min={1} max={10}
                  className="w-full accent-purple-500"
                  value={newJob.priority}
                  onChange={e => setNewJob(j => ({ ...j, priority: Number(e.target.value) }))} />
                <div className="flex justify-between text-[10px] text-gray-600">
                  <span>1 Low</span>
                  <span className={`text-xs font-medium ${newJob.priority >= 7 ? 'text-orange-400' : 'text-gray-300'}`}>
                    {PRIORITY_LABELS[newJob.priority] || 'Medium'}
                  </span>
                  <span>10 High</span>
                </div>
              </div>
              <div className="flex items-end gap-2">
                <button onClick={handleCreate} className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium">
                  Create
                </button>
                <button onClick={() => setShowNewForm(false)} className="text-xs text-gray-500 hover:text-gray-400">
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-12"><RefreshCw size={20} className="text-purple-500 animate-spin" /></div>
        ) : jobs.length === 0 ? (
          <div className="flex items-center justify-center py-12 text-xs text-gray-600">No scan jobs. Create one to get started.</div>
        ) : (
          <>
            {/* Active Queue */}
            {activeQueue.length > 0 && viewMode === 'all' && (
              <div>
                <div className="text-xs font-medium text-gray-400 mb-2 flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-purple-500" />
                  Active Queue ({activeQueue.length})
                </div>
                <div className="space-y-2">
                  {activeQueue.map(job => (
                    <JobRow key={job.id} job={job} loading={actionLoading === job.id}
                      onStart={() => handleStart(job.id)}
                      onCancel={() => handleCancel(job.id)}
                      onPriorityUp={() => handlePriorityChange(job.id, 1)}
                      onPriorityDown={() => handlePriorityChange(job.id, -1)}
                    />
                  ))}
                </div>
              </div>
            )}

            {/* Queue View */}
            {viewMode === 'queue' && (
              <div>
                <div className="text-xs font-medium text-gray-400 mb-2 flex items-center gap-2">
                  <Layers size={14} className="text-purple-400" />
                  Queue Order (priority desc, oldest first)
                </div>
                <div className="space-y-2">
                  {activeQueue.length === 0 ? (
                    <div className="text-xs text-gray-600 py-4 text-center">Queue is empty</div>
                  ) : (
                    activeQueue.map((job, idx) => (
                      <JobRow key={job.id} job={job} index={idx + 1} loading={actionLoading === job.id}
                        onStart={() => handleStart(job.id)}
                        onCancel={() => handleCancel(job.id)}
                        onPriorityUp={() => handlePriorityChange(job.id, 1)}
                        onPriorityDown={() => handlePriorityChange(job.id, -1)}
                      />
                    ))
                  )}
                </div>
              </div>
            )}

            {/* Completed */}
            {viewMode === 'all' && completedJobs.length > 0 && (
              <div>
                <div className="text-xs font-medium text-gray-400 mb-2">Completed</div>
                <div className="space-y-1">
                  {completedJobs.slice(0, 20).map(job => (
                    <JobRow key={job.id} job={job} compact />
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

function JobRow({ job, index, loading, onStart, onCancel, onPriorityUp, onPriorityDown, compact }: {
  job: ScanJob; index?: number; loading?: boolean; onStart?: () => void; onCancel?: () => void;
  onPriorityUp?: () => void; onPriorityDown?: () => void; compact?: boolean;
}) {
  const priority = (job as any).priority ?? 5
  return (
    <div className={`bg-gray-900 border border-gray-800 rounded-lg ${compact ? 'p-2' : 'p-3'} hover:border-gray-700 transition-colors`}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0 flex-1">
          {index !== undefined && <span className="text-[10px] text-gray-600 w-4">#{index}</span>}
          <div className={`w-2 h-2 rounded-full ${STATUS_COLORS[job.status]?.split(' ')[0] || 'bg-gray-500'}`} />
          <span className="text-xs font-mono text-gray-200 truncate">{job.target_url || job.scan_type}</span>
          <span className={`text-[10px] px-1.5 py-0.5 rounded ${STATUS_COLORS[job.status] || 'text-gray-400 bg-gray-500/10'}`}>
            {job.status}
          </span>
          {!compact && job.status === 'running' && <span className="text-[10px] text-gray-500">({job.progress}%)</span>}
        </div>

        <div className="flex items-center gap-1">
          {/* Priority controls */}
          {!compact && (job.status === 'pending' || job.status === 'running') && (
            <div className="flex items-center gap-1 mr-2">
              <button onClick={onPriorityDown} className="p-0.5 text-gray-600 hover:text-gray-400" title="Lower priority">
                <ArrowDown size={10} />
              </button>
              <div className="flex items-center gap-1">
                <div className={`w-2 h-2 rounded-full ${PRIORITY_COLORS[priority] || 'bg-gray-500'}`} />
                <span className="text-[10px] text-gray-500">{priority}</span>
              </div>
              <button onClick={onPriorityUp} className="p-0.5 text-gray-600 hover:text-gray-400" title="Raise priority">
                <ArrowUp size={10} />
              </button>
            </div>
          )}

          {/* Actions */}
          {job.status === 'pending' && onStart && (
            <button onClick={onStart} disabled={loading}
              className="p-1 text-green-400 hover:text-green-300 disabled:opacity-50" title="Start">
              <Play size={12} />
            </button>
          )}
          {job.status === 'running' && onCancel && (
            <button onClick={onCancel} disabled={loading}
              className="p-1 text-red-400 hover:text-red-300 disabled:opacity-50" title="Cancel">
              <XCircle size={12} />
            </button>
          )}
        </div>
      </div>

      {/* Progress bar for running jobs */}
      {!compact && job.status === 'running' && (
        <div className="mt-2 h-1 bg-gray-800 rounded-full overflow-hidden">
          <div className="h-full bg-gradient-to-r from-purple-600 to-purple-400 rounded-full transition-all duration-500"
            style={{ width: `${Math.min(job.progress ?? 0, 100)}%` }} />
        </div>
      )}

      {/* Timing info */}
      {!compact && (job.created_at as any) && (
        <div className="flex items-center gap-3 mt-1.5 text-[10px] text-gray-600">
          <span>Created: {new Date(job.created_at as any).toLocaleString()}</span>
          {(job as any).started_at && <span>Started: {new Date((job as any).started_at).toLocaleString()}</span>}
        </div>
      )}
    </div>
  )
}

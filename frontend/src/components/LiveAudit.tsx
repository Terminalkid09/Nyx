import { useState, useEffect, useCallback } from 'react'
import { Play, StopCircle, Activity, AlertTriangle, CheckCircle, XCircle, Settings, Sliders } from 'lucide-react'
import {
  fetchLiveAuditStatus,
  startLiveAudit,
  stopLiveAudit,
  updateLiveAuditConfig,
  clearAuditStats,
  clearAuditLog,
} from '../api/endpoints/liveAudit'

interface AuditStatus {
  running: boolean
  config: {
    passive_scan: boolean
    active_scan: boolean
    param_discovery: boolean
    fuzz_discovered: boolean
    max_concurrent_audits: number
    scope_only: boolean
    throttle_ms: number
    log_all: boolean
  }
  stats: {
    requests_analyzed: number
    responses_analyzed: number
    passive_findings: number
    active_scans_queued: number
    active_scans_completed: number
    active_findings: number
    errors: number
    started_at: string | null
  }
  audit_log_count: number
  recent_log: Array<{
    timestamp: string
    type: string
    data: Record<string, any>
  }>
}

export function LiveAudit() {
  const [status, setStatus] = useState<AuditStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [configOpen, setConfigOpen] = useState(false)
  const [showStopConfirm, setShowStopConfirm] = useState(false)

  const loadStatus = useCallback(async () => {
    try {
      const data = await fetchLiveAuditStatus()
      setStatus(data)
      setError('')
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadStatus()
    const interval = setInterval(() => {
      if (status?.running) {
        loadStatus()
      }
    }, 3000)
    return () => clearInterval(interval)
  }, [loadStatus, status?.running])

  const handleStart = async () => {
    try {
      await startLiveAudit()
      await loadStatus()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleStop = async () => {
    try {
      await stopLiveAudit()
      setShowStopConfirm(false)
      await loadStatus()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleConfigUpdate = async (key: string, value: any) => {
    if (!status) return
    try {
      const updated = await updateLiveAuditConfig({ [key]: value })
      setStatus((prev) => prev ? { ...prev, config: updated } : prev)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleClearStats = async () => {
    try {
      await clearAuditStats()
      await loadStatus()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleClearLog = async () => {
    try {
      await clearAuditLog()
      await loadStatus()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-gray-500">
        Loading Live Audit...
      </div>
    )
  }

  if (!status) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-red-400">
        Failed to load Live Audit status.
      </div>
    )
  }

  const { running, config, stats, recent_log } = status

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <Activity size={16} />
        <span>Live Audit</span>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>}

        {/* Status Indicator */}
        <div className="bg-gray-900 border border-gray-800 rounded p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-4 h-4 rounded-full ${running ? 'bg-green-500 shadow-lg shadow-green-500/50' : 'bg-red-500 shadow-lg shadow-red-500/50'}`} />
            <span className="text-sm font-medium">{running ? 'Running' : 'Stopped'}</span>
            {running && stats.started_at && (
              <span className="text-xs text-gray-500">
                Started {new Date(stats.started_at).toLocaleTimeString()}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {!running ? (
              <button
                onClick={handleStart}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600 hover:bg-green-500 text-white text-xs font-medium rounded transition-colors"
              >
                <Play size={14} />
                Start
              </button>
            ) : showStopConfirm ? (
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-400">Stop audit?</span>
                <button
                  onClick={handleStop}
                  className="px-2 py-1 bg-red-600 hover:bg-red-500 text-white text-xs rounded transition-colors"
                >
                  Yes
                </button>
                <button
                  onClick={() => setShowStopConfirm(false)}
                  className="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-200 text-xs rounded transition-colors"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={() => setShowStopConfirm(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white text-xs font-medium rounded transition-colors"
              >
                <StopCircle size={14} />
                Stop
              </button>
            )}
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-gray-900 border border-gray-800 rounded p-3">
            <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
              <Activity size={12} />
              <span>Requests</span>
            </div>
            <div className="text-lg font-semibold text-gray-100">{stats.requests_analyzed}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded p-3">
            <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
              <Activity size={12} />
              <span>Responses</span>
            </div>
            <div className="text-lg font-semibold text-gray-100">{stats.responses_analyzed}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded p-3">
            <div className="flex items-center gap-1.5 text-xs text-orange-400 mb-1">
              <AlertTriangle size={12} />
              <span>Passive Findings</span>
            </div>
            <div className="text-lg font-semibold text-orange-300">{stats.passive_findings}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded p-3">
            <div className="flex items-center gap-1.5 text-xs text-red-400 mb-1">
              <XCircle size={12} />
              <span>Errors</span>
            </div>
            <div className="text-lg font-semibold text-red-300">{stats.errors}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded p-3">
            <div className="flex items-center gap-1.5 text-xs text-purple-400 mb-1">
              <CheckCircle size={12} />
              <span>Active Queued</span>
            </div>
            <div className="text-lg font-semibold text-purple-300">{stats.active_scans_queued}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded p-3">
            <div className="flex items-center gap-1.5 text-xs text-purple-400 mb-1">
              <CheckCircle size={12} />
              <span>Active Completed</span>
            </div>
            <div className="text-lg font-semibold text-purple-300">{stats.active_scans_completed}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded p-3">
            <div className="flex items-center gap-1.5 text-xs text-red-400 mb-1">
              <AlertTriangle size={12} />
              <span>Active Findings</span>
            </div>
            <div className="text-lg font-semibold text-red-300">{stats.active_findings}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded p-3">
            <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
              <Activity size={12} />
              <span>Audit Log</span>
            </div>
            <div className="text-lg font-semibold text-gray-100">{status.audit_log_count}</div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex gap-2">
          <button
            onClick={handleClearStats}
            className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs rounded transition-colors"
          >
            Clear Stats
          </button>
          <button
            onClick={handleClearLog}
            className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs rounded transition-colors"
          >
            Clear Log
          </button>
        </div>

        {/* Config Panel */}
        <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
          <button
            onClick={() => setConfigOpen(!configOpen)}
            className="w-full flex items-center gap-2 px-3 py-2 text-xs font-medium text-gray-300 hover:bg-gray-800 transition-colors"
          >
            <Settings size={14} />
            <span>Audit Configuration</span>
            <Sliders
              size={14}
              className={`ml-auto transition-transform ${configOpen ? 'rotate-180' : ''}`}
            />
          </button>
          {configOpen && (
            <div className="p-3 border-t border-gray-800 space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <label className="flex items-center gap-2 text-xs text-gray-400">
                  <input
                    type="checkbox"
                    checked={config.passive_scan}
                    onChange={(e) => handleConfigUpdate('passive_scan', e.target.checked)}
                    className="accent-purple-500"
                  />
                  Passive Scan
                </label>
                <label className="flex items-center gap-2 text-xs text-gray-400">
                  <input
                    type="checkbox"
                    checked={config.active_scan}
                    onChange={(e) => handleConfigUpdate('active_scan', e.target.checked)}
                    className="accent-purple-500"
                  />
                  Active Scan
                </label>
                <label className="flex items-center gap-2 text-xs text-gray-400">
                  <input
                    type="checkbox"
                    checked={config.scope_only}
                    onChange={(e) => handleConfigUpdate('scope_only', e.target.checked)}
                    className="accent-purple-500"
                  />
                  Scope Only
                </label>
                <label className="flex items-center gap-2 text-xs text-gray-400">
                  <input
                    type="checkbox"
                    checked={config.param_discovery}
                    onChange={(e) => handleConfigUpdate('param_discovery', e.target.checked)}
                    className="accent-purple-500"
                  />
                  Param Discovery
                </label>
                <label className="flex items-center gap-2 text-xs text-gray-400">
                  <input
                    type="checkbox"
                    checked={config.fuzz_discovered}
                    onChange={(e) => handleConfigUpdate('fuzz_discovered', e.target.checked)}
                    className="accent-purple-500"
                  />
                  Fuzz Discovered
                </label>
                <label className="flex items-center gap-2 text-xs text-gray-400">
                  <input
                    type="checkbox"
                    checked={config.log_all}
                    onChange={(e) => handleConfigUpdate('log_all', e.target.checked)}
                    className="accent-purple-500"
                  />
                  Verbose Logging
                </label>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-gray-800">
                <div className="flex flex-col gap-1">
                  <div className="flex items-center justify-between text-xs text-gray-400">
                    <span>Max Concurrent Audits</span>
                    <span className="font-mono text-gray-200">{config.max_concurrent_audits}</span>
                  </div>
                  <input
                    type="range"
                    min={1}
                    max={10}
                    value={config.max_concurrent_audits}
                    onChange={(e) => handleConfigUpdate('max_concurrent_audits', parseInt(e.target.value))}
                    className="w-full accent-purple-500"
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <div className="flex items-center justify-between text-xs text-gray-400">
                    <span>Throttle (ms)</span>
                    <span className="font-mono text-gray-200">{config.throttle_ms}ms</span>
                  </div>
                  <input
                    type="range"
                    min={0}
                    max={2000}
                    step={50}
                    value={config.throttle_ms}
                    onChange={(e) => handleConfigUpdate('throttle_ms', parseInt(e.target.value))}
                    className="w-full accent-purple-500"
                  />
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Audit Log */}
        {config.log_all && (
          <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
            <div className="px-3 py-2 border-b border-gray-800 text-xs font-medium text-gray-400">
              Audit Log ({recent_log.length})
            </div>
            <div className="max-h-60 overflow-y-auto">
              {recent_log.length === 0 ? (
                <div className="p-4 text-xs text-gray-500 text-center">No audit entries yet.</div>
              ) : (
                recent_log.slice().reverse().map((entry, i) => (
                  <div
                    key={i}
                    className="px-3 py-1.5 border-b border-gray-800 last:border-0 text-xs flex items-start gap-2"
                  >
                    <span className="text-gray-500 shrink-0 w-16">
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </span>
                    <span className="text-purple-400 shrink-0">{entry.type}</span>
                    <span className="text-gray-400 truncate">
                      {entry.data.url || entry.data.method || JSON.stringify(entry.data)}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

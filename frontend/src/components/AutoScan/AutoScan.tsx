import { useState, useEffect, useRef } from 'react'
import { Activity, List, Play, Settings } from 'lucide-react'
import {
  fetchDiscoveredUrls,
  fetchPendingScans,
  updateAutoScanConfig,
  getAutoScanConfig,
} from '../../api/endpoints/automation'

interface DiscoveredUrl {
  url: string
  source: string
  timestamp: string
  host: string
}

interface PendingScan {
  url: string
  priority: number
}

interface AutoScanConfig {
  auto_active_scan: boolean
  max_concurrent: number
  scan_delay_ms: number
}

const SOURCE_LABELS: Record<string, string> = {
  request: 'Request',
  request_extracted: 'Request (extracted)',
  response_body: 'Response Body',
  redirect: 'Redirect',
  api_endpoint: 'API Endpoint',
}

export function AutoScan() {
  const [discovered, setDiscovered] = useState<DiscoveredUrl[]>([])
  const [pending, setPending] = useState<PendingScan[]>([])
  const [config, setConfig] = useState<AutoScanConfig>({
    auto_active_scan: true,
    max_concurrent: 3,
    scan_delay_ms: 500,
  })
  const [domainFilter, setDomainFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [recentUrls, setRecentUrls] = useState<Set<string>>(new Set())
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const loadData = () => {
    Promise.all([
      fetchDiscoveredUrls(),
      fetchPendingScans(),
      getAutoScanConfig(),
    ])
      .then(([d, p, c]) => {
        setDiscovered(d)
        setPending(p)
        setConfig(c)
      })
      .catch((err: any) => setError(err.response?.data?.detail || err.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
    pollingRef.current = setInterval(loadData, 5000)
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [])

  const handleConfigUpdate = async (updates: Partial<AutoScanConfig>) => {
    try {
      const updated = await updateAutoScanConfig(updates)
      setConfig(updated)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleTriggerScan = async (url: string) => {
    setRecentUrls((prev) => new Set(prev).add(url))
    setTimeout(() => {
      setRecentUrls((prev) => {
        const next = new Set(prev)
        next.delete(url)
        return next
      })
    }, 3000)
  }

  const handleClearQueue = () => {
    setPending([])
  }

  const filteredDiscovered = domainFilter
    ? discovered.filter((d) => d.host.includes(domainFilter))
    : discovered

  const domains = [...new Set(discovered.map((d) => d.host))].sort()

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-gray-500">
        Loading AutoScan...
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <Activity size={16} />
        <span>AutoScan</span>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>}

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {/* Discovered URLs */}
          <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
            <div className="p-2 border-b border-gray-800 text-xs font-medium text-gray-400 flex items-center gap-2">
              <List size={14} />
              <span>Discovered URLs ({filteredDiscovered.length})</span>
              <select
                className="ml-auto bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-300"
                value={domainFilter}
                onChange={(e) => setDomainFilter(e.target.value)}
              >
                <option value="">All domains</option>
                {domains.map((d) => (
                  <option key={d} value={d}>{d}</option>
                ))}
              </select>
            </div>
            <div className="max-h-80 overflow-y-auto">
              {filteredDiscovered.length === 0 ? (
                <div className="p-4 text-xs text-gray-500 text-center">No URLs discovered yet.</div>
              ) : (
                filteredDiscovered.map((item) => (
                  <div
                    key={item.url}
                    className={`px-3 py-2 border-b border-gray-800 last:border-0 text-xs flex items-start gap-2 ${
                      recentUrls.has(item.url) ? 'bg-purple-900/20' : ''
                    }`}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="font-mono text-gray-200 truncate">{item.url}</div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-gray-500 text-[10px]">{item.host}</span>
                        <span className="text-gray-600">·</span>
                        <span className="text-gray-500 text-[10px]">
                          {SOURCE_LABELS[item.source] || item.source}
                        </span>
                        {recentUrls.has(item.url) && (
                          <span className="text-[10px] font-medium text-purple-400 ml-auto">NEW</span>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Pending Active Scans */}
          <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
            <div className="p-2 border-b border-gray-800 text-xs font-medium text-gray-400 flex items-center gap-2">
              <Play size={14} />
              <span>Pending Active Scans ({pending.length})</span>
              {pending.length > 0 && (
                <button
                  onClick={handleClearQueue}
                  className="ml-auto text-red-400 hover:text-red-300 text-[10px]"
                >
                  Clear queue
                </button>
              )}
            </div>
            <div className="max-h-80 overflow-y-auto">
              {pending.length === 0 ? (
                <div className="p-4 text-xs text-gray-500 text-center">No pending scans.</div>
              ) : (
                pending.map((item) => (
                  <div
                    key={item.url}
                    className="px-3 py-2 border-b border-gray-800 last:border-0 text-xs flex items-center gap-2"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="font-mono text-gray-200 truncate">{item.url}</div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span
                          className={`text-[10px] font-medium px-1 rounded ${
                            item.priority > 1
                              ? 'bg-orange-500/20 text-orange-400'
                              : 'bg-gray-700 text-gray-400'
                          }`}
                        >
                          P{item.priority}
                        </span>
                      </div>
                    </div>
                    <button
                      onClick={() => handleTriggerScan(item.url)}
                      className="p-1 text-purple-400 hover:text-purple-300"
                      title="Trigger scan now"
                    >
                      <Play size={14} />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Automation Config */}
        <div className="bg-gray-900 border border-gray-800 rounded p-3">
          <div className="flex items-center gap-2 mb-3">
            <Settings size={14} className="text-gray-400" />
            <span className="text-xs font-medium text-gray-300">Automation Config</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <label className="flex items-center gap-2 text-xs text-gray-400">
              <input
                type="checkbox"
                checked={config.auto_active_scan}
                onChange={(e) => handleConfigUpdate({ auto_active_scan: e.target.checked })}
                className="accent-purple-500"
              />
              Auto Active Scan
            </label>
            <div className="flex items-center gap-2 text-xs text-gray-400">
              <span>Max Concurrent:</span>
              <input
                type="number"
                min={1}
                max={20}
                value={config.max_concurrent}
                onChange={(e) => handleConfigUpdate({ max_concurrent: parseInt(e.target.value) || 1 })}
                className="w-16 bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-200"
              />
            </div>
            <div className="flex items-center gap-2 text-xs text-gray-400">
              <span>Scan Delay (ms):</span>
              <input
                type="number"
                min={100}
                max={30000}
                step={100}
                value={config.scan_delay_ms}
                onChange={(e) => handleConfigUpdate({ scan_delay_ms: parseInt(e.target.value) || 500 })}
                className="w-20 bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-200"
              />
            </div>
          </div>
        </div>
        
        {/* Webhooks Config */}
        <WebhooksConfig />
      </div>
    </div>
  )
}

function WebhooksConfig() {
  const [webhooks, setWebhooks] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [newUrl, setNewUrl] = useState('')
  const [newType, setNewType] = useState('slack')

  const loadWebhooks = async () => {
    try {
      const { fetchWebhooks } = await import('../../api/endpoints/automation')
      const data = await fetchWebhooks()
      setWebhooks(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadWebhooks()
  }, [])

  const handleAdd = async () => {
    if (!newUrl) return
    try {
      const { createWebhook } = await import('../../api/endpoints/automation')
      await createWebhook({
        name: `${newType} Webhook`,
        type: newType,
        url: newUrl,
        enabled: true,
        events: ['finding.created']
      })
      setNewUrl('')
      loadWebhooks()
    } catch (err) {
      console.error(err)
    }
  }

  const handleToggle = async (id: string, enabled: boolean) => {
    try {
      const { updateWebhook } = await import('../../api/endpoints/automation')
      await updateWebhook(id, { enabled })
      loadWebhooks()
    } catch (err) {
      console.error(err)
    }
  }

  const handleDelete = async (id: string) => {
    try {
      const { deleteWebhook } = await import('../../api/endpoints/automation')
      await deleteWebhook(id)
      loadWebhooks()
    } catch (err) {
      console.error(err)
    }
  }

  const handleTest = async (id: string) => {
    try {
      const { testWebhook } = await import('../../api/endpoints/automation')
      await testWebhook(id)
      alert('Test alert sent!')
    } catch (err) {
      console.error(err)
      alert('Failed to send test alert')
    }
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded p-3 mt-4">
      <div className="flex items-center gap-2 mb-3">
        <div className="w-2 h-2 bg-purple-500 rounded-full" />
        <span className="text-xs font-medium text-gray-300">Webhooks & Alerts</span>
      </div>
      
      <div className="flex flex-col gap-3">
        {loading ? (
          <div className="text-xs text-gray-500">Loading webhooks...</div>
        ) : webhooks.length === 0 ? (
          <div className="text-xs text-gray-500">No webhooks configured.</div>
        ) : (
          webhooks.map(wh => (
            <div key={wh.id} className="flex items-center gap-3 text-xs bg-gray-800 p-2 rounded border border-gray-700">
              <input
                type="checkbox"
                checked={wh.enabled}
                onChange={(e) => handleToggle(wh.id, e.target.checked)}
                className="accent-purple-500"
              />
              <span className="font-medium text-gray-300 uppercase">{wh.type}</span>
              <span className="text-gray-500 truncate flex-1">{wh.url}</span>
              <button onClick={() => handleTest(wh.id)} className="text-purple-400 hover:text-purple-300 px-2">Test</button>
              <button onClick={() => handleDelete(wh.id)} className="text-red-400 hover:text-red-300 px-2">Delete</button>
            </div>
          ))
        )}

        <div className="flex items-center gap-2 mt-2">
          <select
            value={newType}
            onChange={(e) => setNewType(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
          >
            <option value="slack">Slack</option>
            <option value="discord">Discord</option>
          </select>
          <input
            type="text"
            placeholder="Webhook URL (https://...)"
            value={newUrl}
            onChange={(e) => setNewUrl(e.target.value)}
            className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
          />
          <button
            onClick={handleAdd}
            disabled={!newUrl}
            className="bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white px-3 py-1 rounded text-xs font-medium transition-colors"
          >
            Add Webhook
          </button>
        </div>
      </div>
    </div>
  )
}

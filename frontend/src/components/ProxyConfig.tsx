import { useState, useEffect } from 'react'
import { apiClient } from '../api/client'
import { Info } from 'lucide-react'

interface ProxyConfig {
  id?: string
  enabled: boolean
  host: string
  port: number
  protocol: 'HTTP' | 'HTTPS' | 'SOCKS5'
  dns_resolution: 'proxy' | 'local'
  auth_enabled: boolean
  username: string
  password: string
  scope_only: boolean
  exclude_hosts: string[]
}

interface LogEntry {
  timestamp: string
  message: string
}

const emptyConfig: ProxyConfig = {
  enabled: false,
  host: '',
  port: 8080,
  protocol: 'HTTP',
  dns_resolution: 'proxy',
  auth_enabled: false,
  username: '',
  password: '',
  scope_only: false,
  exclude_hosts: [],
}

export function ProxyConfigPage() {
  const [config, setConfig] = useState<ProxyConfig>(emptyConfig)
  const [configId, setConfigId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ success: boolean; ip?: string; error?: string } | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [authOpen, setAuthOpen] = useState(false)
  const [scopeOpen, setScopeOpen] = useState(false)
  const [excludeText, setExcludeText] = useState('')
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [localIps, setLocalIps] = useState<string[]>([])

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const configResp = await apiClient.get('/api/proxy-config/')
        if (cancelled) return
        if (configResp.data && configResp.data.id) {
          const data = configResp.data
          setConfigId(data.id)
          setConfig({
            enabled: data.enabled ?? false,
            host: data.host || '',
            port: data.port ?? 8080,
            protocol: data.protocol || 'HTTP',
            dns_resolution: data.dns_resolution || 'proxy',
            auth_enabled: data.auth_enabled ?? false,
            username: data.username || '',
            password: data.password || '',
            scope_only: data.scope_only ?? false,
            exclude_hosts: data.exclude_hosts || [],
          })
          setExcludeText((data.exclude_hosts || []).join('\n'))
          setAuthOpen(data.auth_enabled ?? false)
          setScopeOpen(data.scope_only ?? false)
        }
      } catch {}
      if (!cancelled) setLoading(false)
    }
    load()
    fetch('/api/proxy-config/local-ips').then(r => r.json()).then(d => { if (d.ips) setLocalIps(d.ips) }).catch(() => {})
    return () => { cancelled = true }
  }, [])

  const addLog = (message: string) => {
    setLogs((prev) => [...prev.slice(-99), { timestamp: new Date().toLocaleTimeString(), message }])
  }

  const handleToggle = async () => {
    const nextEnabled = !config.enabled
    setConfig((prev) => ({ ...prev, enabled: nextEnabled }))
    addLog(nextEnabled ? 'Proxy enabled' : 'Proxy disabled')
    if (configId) {
      try {
        const { data } = await apiClient.post(`/api/proxy-config/${configId}/toggle`)
        setConfig((prev) => ({ ...prev, enabled: data.enabled }))
      } catch {
        setConfig((prev) => ({ ...prev, enabled: !nextEnabled }))
        setError('Failed to toggle proxy')
      }
    }
  }

  const handleTest = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const { data } = await apiClient.post('/api/proxy-config/test', {
        host: config.host,
        port: config.port,
        protocol: config.protocol,
        username: config.auth_enabled ? config.username : '',
        password: config.auth_enabled ? config.password : '',
        auth_enabled: config.auth_enabled,
      })
      setTestResult({ success: true, ip: data.ip || data.external_ip || 'connected' })
      addLog(`Connection test succeeded — IP: ${data.ip || data.external_ip || 'connected'}`)
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || 'Connection failed'
      setTestResult({ success: false, error: msg })
      addLog(`Connection test failed — ${msg}`)
    } finally {
      setTesting(false)
    }
  }

  const handleSave = async () => {
    setSaving(true)
    setError('')
    const body = {
      ...config,
      exclude_hosts: excludeText
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.length > 0),
    }
    try {
      if (configId) {
        const { data } = await apiClient.put(`/api/proxy-config/${configId}`, body)
        setConfigId(data.id)
        addLog('Proxy configuration updated')
      } else {
        const { data } = await apiClient.post('/api/proxy-config/', body)
        setConfigId(data.id)
        addLog('Proxy configuration created')
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  const set = <K extends keyof ProxyConfig>(key: K, value: ProxyConfig[K]) => {
    setConfig((prev) => ({ ...prev, [key]: value }))
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <span className="text-gray-500 text-sm">Loading proxy configuration...</span>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300">
        Upstream Proxy Configuration
      </div>

      <div className="flex-1 p-4 space-y-4 overflow-auto">
        {error && (
          <div className="bg-red-900/50 border border-red-800 rounded px-3 py-2 text-xs text-red-300">{error}</div>
        )}

        <div className="flex items-center justify-between bg-gray-900 border border-gray-800 rounded p-3">
          <div>
            <div className="text-sm text-gray-200 font-medium">Proxy Enabled</div>
            <div className="text-xs text-gray-500 mt-0.5">
              {config.enabled
                ? 'All Nyx tools will route traffic through this proxy'
                : 'Traffic will be sent directly'}
            </div>
          </div>
          <button
            onClick={handleToggle}
            className={`relative w-12 h-6 rounded-full transition-colors ${
              config.enabled ? 'bg-purple-600' : 'bg-gray-700'
            }`}
          >
            <span
              className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${
                config.enabled ? 'translate-x-6' : 'translate-x-0'
              }`}
            />
          </button>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-gray-500 block mb-1">Protocol</label>
            <select
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
              value={config.protocol}
              onChange={(e) => set('protocol', e.target.value as ProxyConfig['protocol'])}
            >
              <option value="HTTP">HTTP</option>
              <option value="HTTPS">HTTPS</option>
              <option value="SOCKS5">SOCKS5</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-500 block mb-1">DNS Resolution</label>
            <select
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
              value={config.dns_resolution}
              onChange={(e) => set('dns_resolution', e.target.value as ProxyConfig['dns_resolution'])}
            >
              <option value="proxy">Proxy (use proxy DNS)</option>
              <option value="local">Local (resolve locally)</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-4 gap-4">
          <div className="col-span-3">
            <label className="text-xs text-gray-500 block mb-1">Host</label>
            <input
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
              placeholder={localIps.length > 0 ? `e.g. ${localIps[0]} (your IP)` : 'e.g. 192.168.1.100 (your PC IP)'}
              value={config.host}
              onChange={(e) => set('host', e.target.value)}
            />
            {localIps.length > 0 && (
              <div className="flex items-center gap-1 mt-1">
                <Info size={10} className="text-gray-600 shrink-0" />
                <span className="text-[10px] text-gray-600">Your local IPs: {localIps.join(', ')}</span>
              </div>
            )}
          </div>
          <div>
            <label className="text-xs text-gray-500 block mb-1">Port</label>
            <input
              type="number"
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
              value={config.port}
              onChange={(e) => set('port', Number(e.target.value))}
              min={1}
              max={65535}
            />
          </div>
        </div>

        <div className="border border-gray-800 rounded overflow-hidden">
          <button
            className="w-full flex items-center justify-between px-3 py-2 bg-gray-900 hover:bg-gray-800/50 text-xs text-gray-300 font-medium"
            onClick={() => setAuthOpen(!authOpen)}
          >
            <span>Authentication</span>
            <span className={`transform transition-transform ${authOpen ? 'rotate-90' : ''}`}>▶</span>
          </button>
          {authOpen && (
            <div className="p-3 space-y-3">
              <label className="flex items-center gap-2 text-xs text-gray-300">
                <input
                  type="checkbox"
                  className="accent-purple-500"
                  checked={config.auth_enabled}
                  onChange={(e) => set('auth_enabled', e.target.checked)}
                />
                Enable authentication
              </label>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-gray-500 block mb-1">Username</label>
                  <input
                    className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                    placeholder="username"
                    value={config.username}
                    onChange={(e) => set('username', e.target.value)}
                    disabled={!config.auth_enabled}
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-500 block mb-1">Password</label>
                  <input
                    type="password"
                    className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                    placeholder="••••••••"
                    value={config.password}
                    onChange={(e) => set('password', e.target.value)}
                    disabled={!config.auth_enabled}
                  />
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="border border-gray-800 rounded overflow-hidden">
          <button
            className="w-full flex items-center justify-between px-3 py-2 bg-gray-900 hover:bg-gray-800/50 text-xs text-gray-300 font-medium"
            onClick={() => setScopeOpen(!scopeOpen)}
          >
            <span>Scope</span>
            <span className={`transform transition-transform ${scopeOpen ? 'rotate-90' : ''}`}>▶</span>
          </button>
          {scopeOpen && (
            <div className="p-3 space-y-3">
              <label className="flex items-center gap-2 text-xs text-gray-300">
                <input
                  type="checkbox"
                  className="accent-purple-500"
                  checked={config.scope_only}
                  onChange={(e) => set('scope_only', e.target.checked)}
                />
                Use only for in-scope items
              </label>
              <div>
                <label className="text-xs text-gray-500 block mb-1">Exclude hosts (one per line)</label>
                <textarea
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono resize-none"
                  rows={4}
                  placeholder="*.internal.com&#10;localhost&#10;127.0.0.1"
                  value={excludeText}
                  onChange={(e) => setExcludeText(e.target.value)}
                />
              </div>
            </div>
          )}
        </div>

        <div className="flex gap-2 items-center pt-2 border-t border-gray-800">
          <button
            className="bg-purple-600 hover:bg-purple-700 px-4 py-1.5 rounded text-xs font-medium disabled:opacity-50 flex items-center gap-2"
            onClick={handleSave}
            disabled={saving || !config.host}
          >
            {saving ? 'Saving...' : 'Save'}
          </button>
          <button
            className={`px-3 py-1.5 rounded text-xs font-medium disabled:opacity-50 flex items-center gap-2 ${
              testResult?.success
                ? 'bg-green-700 text-green-200'
                : testResult && !testResult.success
                ? 'bg-red-700 text-red-200'
                : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
            }`}
            onClick={handleTest}
            disabled={testing || !config.host}
          >
            {testing ? (
              <>
                <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Testing...
              </>
            ) : testResult?.success ? (
              <>✓ {testResult.ip}</>
            ) : testResult && !testResult.success ? (
              <>✗ {testResult.error}</>
            ) : (
              'Test Connection'
            )}
          </button>
        </div>

        {logs.length > 0 && (
          <div className="border border-gray-800 rounded overflow-hidden">
            <div className="px-3 py-2 border-b border-gray-800 text-xs text-gray-400 font-medium">Proxy Log</div>
            <div className="max-h-32 overflow-y-auto bg-gray-900/50">
              {logs.map((entry, idx) => (
                <div key={idx} className="px-3 py-1 text-[10px] text-gray-500 font-mono border-b border-gray-800/30 flex gap-2">
                  <span className="text-gray-600 shrink-0">{entry.timestamp}</span>
                  <span>{entry.message}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

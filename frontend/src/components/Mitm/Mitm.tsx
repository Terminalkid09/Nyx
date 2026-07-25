import { useState, useEffect, useCallback } from 'react'
import { getMitmStatus, startMitm, stopMitm, MitmStatus } from '../../api/endpoints/mitm'
import { Shield, Play, Square, Globe, Radio, Signal, Wifi, Download } from 'lucide-react'

const statusColor = (ok: boolean) => ok ? 'text-green-400' : 'text-red-400'
const bgStatus = (ok: boolean) => ok ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'

export function MitmPage() {
  const [status, setStatus] = useState<MitmStatus | null>(null)
  const [targetIp, setTargetIp] = useState('192.168.1.210')
  const [gatewayIp, setGatewayIp] = useState('192.168.1.1')
  const [enableDns, setEnableDns] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [poll, setPoll] = useState<ReturnType<typeof setInterval> | null>(null)

  const fetchStatus = useCallback(async () => {
    try {
      const s = await getMitmStatus()
      setStatus(s)
      if (s.target_ip) setTargetIp(s.target_ip)
      if (s.gateway_ip) setGatewayIp(s.gateway_ip)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    fetchStatus()
    const id = setInterval(fetchStatus, 3000)
    setPoll(id)
    return () => { clearInterval(id) }
  }, [fetchStatus])

  const handleStart = async () => {
    setLoading(true)
    setError(null)
    try {
      await startMitm({ target_ip: targetIp, gateway_ip: gatewayIp, enable_dns_spoof: enableDns })
      // Fetch real status right after start to get all fields including admin_mode correctly
      const s = await getMitmStatus()
      setStatus(s)
    } catch (e: any) {
      setError(e.response?.data?.detail || e.message || 'Failed to start MITM')
    } finally {
      setLoading(false)
    }
  }

  const handleStop = async () => {
    setLoading(true)
    setError(null)
    try {
      await stopMitm()
      setStatus({ active: false, arp_spoofing: false, dns_spoofing: false, target_ip: null, gateway_ip: null, admin_mode: !!(status?.admin_mode) })
    } catch (e: any) {
      setError(e.response?.data?.detail || e.message || 'Failed to stop MITM')
    } finally {
      setLoading(false)
    }
  }

  const isActive = status?.active ?? false

  return (
    <div className="p-6 h-full overflow-y-auto">
      <div className="max-w-3xl mx-auto">
        <div className="flex items-center gap-3 mb-6">
          <Shield className="text-purple-400" size={28} />
          <div>
            <h1 className="text-xl font-bold text-gray-100">MITM Interception</h1>
            <p className="text-sm text-gray-400">Man-in-the-Middle — ARP spoofing & transparent proxy</p>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div className={`p-4 rounded-lg border ${bgStatus(isActive)}`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-300">Status</span>
              <span className={`text-sm font-bold ${statusColor(isActive)}`}>
                {isActive ? 'ACTIVE' : 'INACTIVE'}
              </span>
            </div>
            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-gray-400">ARP Spoofing</span>
                <span className={statusColor(status?.arp_spoofing ?? false)}>
                  {status?.arp_spoofing ? 'ON' : 'OFF'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">DNS Spoofing</span>
                <span className={statusColor(status?.dns_spoofing ?? false)}>
                  {status?.dns_spoofing ? 'ON' : 'OFF'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Admin Mode</span>
                <span className={statusColor(status?.admin_mode ?? false)}>
                  {status?.admin_mode ? 'YES' : 'NO (dev mode)'}
                </span>
              </div>
            </div>
          </div>

          <div className="p-4 rounded-lg border border-gray-800 bg-gray-900/50">
            <div className="flex items-center gap-2 mb-2">
              <Wifi size={14} className="text-gray-400" />
              <span className="text-sm font-medium text-gray-300">Target</span>
            </div>
            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-gray-400">Device IP</span>
                <span className="text-gray-200 font-mono">{status?.target_ip || '-'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Gateway</span>
                <span className="text-gray-200 font-mono">{status?.gateway_ip || '-'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Proxy Port</span>
                <span className="text-gray-200 font-mono">8080</span>
              </div>
            </div>
          </div>
        </div>

        {!isActive && (
          <div className="p-5 rounded-lg border border-gray-800 bg-gray-900/50 mb-6">
            <h2 className="text-sm font-semibold text-gray-200 mb-4 flex items-center gap-2">
              <Radio size={14} className="text-purple-400" />
              Start Interception
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Target IP</label>
                <input
                  type="text"
                  value={targetIp}
                  onChange={(e) => setTargetIp(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono focus:outline-none focus:ring-1 focus:ring-purple-500"
                  placeholder="e.g. 192.168.1.100"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Gateway IP</label>
                <input
                  type="text"
                  value={gatewayIp}
                  onChange={(e) => setGatewayIp(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono focus:outline-none focus:ring-1 focus:ring-purple-500"
                  placeholder="e.g. 192.168.1.1"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">DNS Spoof</label>
                <div className="flex items-center gap-3 mt-1.5">
                  <button
                    onClick={() => setEnableDns(true)}
                    className={`px-3 py-1.5 text-xs rounded font-medium transition-colors ${enableDns ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400'}`}
                  >
                    ON
                  </button>
                  <button
                    onClick={() => setEnableDns(false)}
                    className={`px-3 py-1.5 text-xs rounded font-medium transition-colors ${!enableDns ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400'}`}
                  >
                    OFF
                  </button>
                </div>
              </div>
            </div>

            <button
              onClick={handleStart}
              disabled={loading || !targetIp || !gatewayIp}
              className="flex items-center gap-2 px-5 py-2.5 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-lg transition-colors"
            >
              <Play size={16} />
              {loading ? 'Starting...' : 'Start Interception'}
            </button>
          </div>
        )}

        {isActive && (
          <div className="p-5 rounded-lg border border-green-500/30 bg-green-500/5 mb-6">
            <div className="flex items-center gap-2 mb-4">
              <Signal size={16} className="text-green-400" />
              <h2 className="text-sm font-semibold text-green-400">Actively Intercepting</h2>
            </div>
            <div className="text-xs text-gray-400 space-y-1 mb-4">
              <p>Traffic from <span className="text-gray-200 font-mono">{status?.target_ip}</span> is being redirected through Nyx proxy.</p>
              <p>Browse to <span className="text-gray-200">http://</span> sites on the target device to see captured requests in the <span className="text-gray-200">Proxy</span> tab.</p>
              {!status?.admin_mode && (
                <p className="text-yellow-400 mt-2">⚠ Running without admin privileges — ARP spoofing may not work. Launch Nyx as administrator for full functionality.</p>
              )}
              {status?.dns_spoofing && (
                <p className="text-blue-400">DNS spoofing active — all DNS queries from target are intercepted.</p>
              )}
            </div>

            <div className="flex gap-3">
              <button
                onClick={handleStop}
                disabled={loading}
                className="flex items-center gap-2 px-5 py-2.5 bg-red-600 hover:bg-red-700 disabled:bg-gray-700 text-white text-sm font-medium rounded-lg transition-colors"
              >
                <Square size={16} />
                {loading ? 'Stopping...' : 'Stop Interception'}
              </button>
              <a
                href="/api/ca-certificate"
                download
                className="flex items-center gap-2 px-5 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-sm font-medium rounded-lg transition-colors border border-gray-700"
              >
                <Download size={16} />
                Download CA
              </a>
            </div>
          </div>
        )}

        <div className="p-4 rounded-lg border border-gray-800 bg-gray-900/30">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">How it works</h3>
          <div className="text-xs text-gray-500 space-y-2 leading-relaxed">
            <p><strong className="text-gray-300">1. ARP Spoofing</strong> — Nyx sends fake ARP packets to the target device, impersonating the gateway. The target sends all its traffic to Nyx instead of the router.</p>
            <p><strong className="text-gray-300">2. Transparent Proxy</strong> — Nyx forwards the traffic to the real destination while logging and allowing inspection. No proxy configuration needed on the target.</p>
            <p><strong className="text-gray-300">3. DNS Spoofing</strong> — (Optional) Nyx responds to all DNS queries from the target, allowing domain-based redirection.</p>
            <p><strong className="text-gray-300">4. Restoration</strong> — When stopped, Nyx sends correct ARP packets to restore the original gateway mapping.</p>
          </div>
        </div>
      </div>
    </div>
  )
}

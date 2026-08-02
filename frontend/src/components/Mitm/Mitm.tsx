import { useEffect, useCallback, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  getMitmStatus,
  startMitm,
  stopMitm,
  scanNetwork,
  MitmStatus,
  NetworkDevice,
} from '../../api/endpoints/mitm'
import { useMitmStore } from '../../store/useMitmStore'
import { DeployBox } from './DeployBox'
import {
  Shield,
  Play,
  Square,
  Radio,
  Signal,
  Wifi,
  Download,
  Search,
  Monitor,
  Smartphone,
  Tv,
  Server,
  HelpCircle,
  Activity,
  ExternalLink,
} from 'lucide-react'

const statusColor = (ok: boolean) => (ok ? 'text-green-400' : 'text-red-400')
const bgStatus = (ok: boolean) =>
  ok
    ? 'bg-green-500/10 border-green-500/30'
    : 'bg-red-500/10 border-red-500/30'

function getDeviceIcon(device: NetworkDevice) {
  const v = (device.vendor || '').toLowerCase()
  const h = (device.hostname || '').toLowerCase()
  if (
    v.includes('apple') ||
    h.includes('iphone') ||
    h.includes('ipad') ||
    h.includes('mac')
  )
    return <Monitor size={14} />
  if (
    v.includes('samsung') ||
    v.includes('oneplus') ||
    v.includes('xiaomi') ||
    v.includes('huawei') ||
    h.includes('android')
  )
    return <Smartphone size={14} />
  if (v.includes('tv') || v.includes('sony') || v.includes('lg'))
    return <Tv size={14} />
  if (
    v.includes('raspberry') ||
    v.includes('intel') ||
    v.includes('vmware') ||
    v.includes('oracle')
  )
    return <Server size={14} />
  return <HelpCircle size={14} />
}

// ─── Separated status state (NOT persisted — always fresh from backend) ──────

export function MitmPage() {
  const navigate = useNavigate()

  // Live backend status (transient — always polled)
  const [status, setStatus] = useState<MitmStatus & { captured_flows?: number } | null>(null)
  const [timeNow, setTimeNow] = useState<number>(Date.now())

  // All persistent UI state comes from the store
  const {
    devices,
    selectedIps,
    gatewayIp,
    enableDns,
    scanning,
    scanAttempted,
    loading,
    error,
    manualIp,
    setDevices,
    toggleDevice,
    selectAll,
    deselectAll,
    addManualIp,
    removeIp,
    setGatewayIp,
    setEnableDns,
    setScanning,
    setScanAttempted,
    setLoading,
    setError,
    setManualIp,
  } = useMitmStore()

  // ── Poll backend status every 3 s ──────────────────────────────────────────
  const fetchStatus = useCallback(async () => {
    try {
      const s = await getMitmStatus()
      setStatus(s as any)
      if ((s as any).gateway_ip) setGatewayIp((s as any).gateway_ip)
    } catch {
      /* ignore */
    }
  }, [setGatewayIp])

  useEffect(() => {
    fetchStatus()
    const id = setInterval(fetchStatus, 3000)
    return () => clearInterval(id)
  }, [fetchStatus])

  // Re-render every 5s so idle-timeout warnings based on last_traffic_seen
  // stay fresh without extra network calls.
  useEffect(() => {
    const id = setInterval(() => setTimeNow(Date.now()), 5000)
    return () => clearInterval(id)
  }, [])

  // ── Handlers ───────────────────────────────────────────────────────────────
  const handleScan = async () => {
    setScanning(true)
    setScanAttempted(true)
    setError(null)
    try {
      const d = await scanNetwork()
      setDevices(d.filter((dev) => !dev.is_local))
      const gw = d.find((dev) => dev.ip === gatewayIp)
      if (gw) setGatewayIp(gw.ip)
    } catch (e: any) {
      setError(
        e.response?.data?.detail || e.message || 'Failed to scan network'
      )
      console.error('Network scan error:', e)
    } finally {
      setScanning(false)
    }
  }

  const handleStart = async () => {
    if (selectedIps.size === 0) return
    setLoading(true)
    setError(null)
    try {
      await startMitm({
        target_ips: Array.from(selectedIps),
        gateway_ip: gatewayIp,
        enable_dns_spoof: enableDns,
      })
      await fetchStatus()
    } catch (e: any) {
      setError(
        e.response?.data?.detail || e.message || 'Failed to start MITM'
      )
    } finally {
      setLoading(false)
    }
  }

  const handleStop = async () => {
    setLoading(true)
    setError(null)
    try {
      await stopMitm()
      setStatus({
        active: false,
        arp_spoofing: false,
        dns_spoofing: false,
        target_ips: [],
        gateway_ip: null,
        admin_mode: !!(status?.admin_mode),
      })
    } catch (e: any) {
      setError(
        e.response?.data?.detail || e.message || 'Failed to stop MITM'
      )
    } finally {
      setLoading(false)
    }
  }

  const handleManualKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') addManualIp()
  }

  const isActive = status?.active ?? false
  const targetIps = status?.target_ips ?? []
  const capturedFlows = (status as any)?.captured_flows ?? 0
  const lastTrafficSeen = (status as any)?.last_traffic_seen as string | null | undefined
  const trafficLastTs = lastTrafficSeen ? new Date(lastTrafficSeen).getTime() : 0
  // "Idle" = redirect/transport is up but no flow has been captured in the
  // last 30s (or none ever). Used to distinguish "fine but quiet" from
  // "something is wrong" without claiming ACTIVE proves traffic works.
  const idleMs = trafficLastTs ? Math.max(0, timeNow - trafficLastTs) : (isActive ? Number.MAX_SAFE_INTEGER : 0)
  const trafficIdle = isActive && (capturedFlows === 0 || idleMs > 30000)

  return (
    <div className="p-6 h-full overflow-y-auto">
      <div className="max-w-4xl mx-auto">
        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div className="flex items-center gap-3 mb-6">
          <Shield className="text-purple-400" size={28} />
          <div>
            <h1 className="text-xl font-bold text-gray-100">
              MITM Interception
            </h1>
            <p className="text-sm text-gray-400">
              Man-in-the-Middle — ARP spoofing &amp; transparent proxy
            </p>
          </div>
        </div>

        {/* ── Error Banner ────────────────────────────────────────────────── */}
        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* ── Status Cards ────────────────────────────────────────────────── */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div className={`p-4 rounded-lg border ${bgStatus(isActive)}`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-300">Status</span>
              <span
                className={`text-sm font-bold ${statusColor(isActive)}`}
              >
                {isActive ? 'ACTIVE' : 'INACTIVE'}
              </span>
            </div>
            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-gray-400">MITM transport</span>
                <span className={statusColor(isActive)}>
                  {isActive ? 'UP' : 'DOWN'}
                </span>
              </div>
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
                <span className="text-gray-400">Flows captured</span>
                <span className={statusColor(capturedFlows > 0)}>
                  {capturedFlows > 0 ? capturedFlows : '0'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Last traffic seen</span>
                <span className={statusColor(!trafficIdle)}>
                  {lastTrafficSeen
                    ? new Date(trafficLastTs).toLocaleTimeString()
                    : isActive
                      ? 'never'
                      : '-'}
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
              <span className="text-sm font-medium text-gray-300">
                Target{targetIps.length !== 1 ? 's' : ''}
              </span>
            </div>
            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-gray-400">
                  Device{targetIps.length !== 1 ? 's' : ''}
                </span>
                <span className="text-gray-200 font-mono text-right">
                  {targetIps.length > 0 ? targetIps.join(', ') : '-'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Count</span>
                <span className="text-gray-200 font-mono">
                  {targetIps.length > 0
                    ? `${targetIps.length} device${targetIps.length !== 1 ? 's' : ''}`
                    : '-'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Gateway</span>
                <span className="text-gray-200 font-mono">
                  {status?.gateway_ip || '-'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* ── Active: Captured Traffic Panel ──────────────────────────────── */}
        {isActive && (
          <div className="p-5 rounded-lg border border-green-500/30 bg-green-500/5 mb-6">
            <div className="flex items-center gap-2 mb-4">
              <Signal size={16} className="text-green-400" />
              <h2 className="text-sm font-semibold text-green-400">
                Actively Intercepting
              </h2>
            </div>

            {/* Traffic counter */}
            <div className="flex items-center gap-4 mb-4 p-3 rounded-lg bg-gray-900/50 border border-gray-700">
              <Activity size={20} className="text-purple-400 shrink-0" />
              <div className="flex-1">
                <div className="text-xs text-gray-400 mb-0.5">
                  Flows captured by proxy
                </div>
                <div className="text-2xl font-mono font-bold text-purple-300">
                  {capturedFlows}
                </div>
              </div>
              <button
                onClick={() => navigate('/proxy')}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/30 text-purple-300 text-xs rounded-lg transition-colors"
              >
                <ExternalLink size={12} />
                View in Proxy
              </button>
            </div>

            <div className="text-xs text-gray-400 space-y-1 mb-4">
              <p>
                Traffic from{' '}
                <span className="text-gray-200 font-mono">
                  {targetIps.join(', ')}
                </span>{' '}
                is being redirected through Nyx proxy.
              </p>
              <p>
                Browse to{' '}
                <span className="text-gray-200">http://</span> sites on the
                target device to see captured requests in the{' '}
                <span className="text-gray-200">Proxy</span> tab.
              </p>
              {!status?.admin_mode && (
                <p className="text-yellow-400 mt-2">
                  ⚠ Running without admin privileges — ARP spoofing may not
                  work. Launch Nyx as administrator for full functionality.
                </p>
              )}
              {status?.dns_spoofing && (
                <p className="text-blue-400">
                  DNS spoofing active — all DNS queries from targets are
                  intercepted.
                </p>
              )}
              {trafficIdle && (
                <div className="mt-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
                  <p className="text-amber-300 font-medium mb-1">
                    ⚠ Transport is up, but no traffic has been observed
                    {lastTrafficSeen ? ' for a while' : ' yet'}.
                  </p>
                  <p className="text-amber-200/80 mb-1">
                    "ACTIVE" means the redirect and spoofing tasks are running —
                    it does not prove traffic is reaching the proxy. Check:
                  </p>
                  <ul className="text-amber-200/70 list-disc list-inside space-y-0.5">
                    <li>
                      <strong>Firewall:</strong> is the proxy port open for LAN
                      devices? (Nyx tries to add a Windows Firewall rule, but it
                      needs Administrator rights.)
                    </li>
                    <li>
                      <strong>CA certificate:</strong> HTTPS traffic is only
                      decryptable after installing the Nyx CA on the target.
                    </li>
                    <li>
                      <strong>QUIC/HTTP3:</strong> browsers increasingly use
                      QUIC (UDP) which bypasses the proxy — disable QUIC on the
                      target (e.g. Chrome flags → quic).
                    </li>
                    <li>
                      <strong>Private DNS / DoH / DoT:</strong> targets using a
                      private DNS provider won't send plain DNS to the router,
                      so DNS spoofing misses them.
                    </li>
                    <li>
                      <strong>Certificate pinning:</strong> apps that pin
                      certificates will reject Nyx's CA and stall the connection.
                    </li>
                    <li>
                      <strong>Target activity:</strong> the device must actually
                      generate HTTP/HTTPS traffic — open a site on the target.
                    </li>
                  </ul>
                </div>
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

        {/* ── Inactive: Setup Panel ────────────────────────────────────────── */}
        {!isActive && (
          <>
            <div className="p-5 rounded-lg border border-gray-800 bg-gray-900/50 mb-6">
              <h2 className="text-sm font-semibold text-gray-200 mb-4 flex items-center gap-2">
                <Radio size={14} className="text-purple-400" />
                Start Interception
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                {/* Manual IP */}
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">
                    Manual Target IP
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={manualIp}
                      onChange={(e) => setManualIp(e.target.value)}
                      onKeyDown={handleManualKeyDown}
                      className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono focus:outline-none focus:ring-1 focus:ring-purple-500"
                      placeholder="e.g. 192.168.1.100"
                    />
                    <button
                      onClick={addManualIp}
                      className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 text-sm rounded-lg transition-colors"
                    >
                      + Add
                    </button>
                  </div>
                </div>

                <div className="flex items-end gap-3">
                  {/* Gateway IP */}
                  <div>
                    <label className="block text-xs text-gray-400 mb-1.5">
                      Gateway IP
                    </label>
                    <input
                      type="text"
                      value={gatewayIp}
                      onChange={(e) => setGatewayIp(e.target.value)}
                      className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono focus:outline-none focus:ring-1 focus:ring-purple-500"
                      placeholder="192.168.1.1"
                    />
                  </div>

                  {/* DNS Spoof toggle */}
                  <div>
                    <label className="block text-xs text-gray-400 mb-1.5">
                      DNS Spoof
                    </label>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setEnableDns(true)}
                        className={`px-3 py-2 text-xs rounded font-medium transition-colors ${
                          enableDns
                            ? 'bg-purple-600 text-white'
                            : 'bg-gray-800 text-gray-400'
                        }`}
                      >
                        ON
                      </button>
                      <button
                        onClick={() => setEnableDns(false)}
                        className={`px-3 py-2 text-xs rounded font-medium transition-colors ${
                          !enableDns
                            ? 'bg-purple-600 text-white'
                            : 'bg-gray-800 text-gray-400'
                        }`}
                      >
                        OFF
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Selected IPs chips */}
              {selectedIps.size > 0 && (
                <div className="flex flex-wrap gap-1.5 mb-4">
                  {Array.from(selectedIps).map((ip) => (
                    <span
                      key={ip}
                      className="inline-flex items-center gap-1 px-2 py-1 bg-purple-500/20 border border-purple-500/30 text-purple-300 text-xs rounded-full"
                    >
                      {ip}
                      <button
                        onClick={() => removeIp(ip)}
                        className="hover:text-purple-100 transition-colors"
                      >
                        &times;
                      </button>
                    </span>
                  ))}
                </div>
              )}

              {/* Scan section */}
              <div className="border-t border-gray-700 pt-4 mb-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-medium text-gray-400">
                    Or discover devices via network scan
                  </span>
                  <button
                    onClick={handleScan}
                    disabled={scanning}
                    className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-lg transition-colors"
                  >
                    <Search
                      size={16}
                      className={scanning ? 'animate-spin' : ''}
                    />
                    {scanning ? 'Scanning...' : 'Scan Network'}
                  </button>
                </div>

                {/* Device table */}
                {devices.length > 0 && (
                  <>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs text-gray-400">
                        {devices.length} device
                        {devices.length !== 1 ? 's' : ''} found
                      </span>
                      <div className="flex gap-2">
                        <button
                          onClick={selectAll}
                          className="text-xs text-purple-400 hover:text-purple-300 transition-colors"
                        >
                          Select All
                        </button>
                        <button
                          onClick={deselectAll}
                          className="text-xs text-gray-400 hover:text-gray-300 transition-colors"
                        >
                          Deselect All
                        </button>
                      </div>
                    </div>

                    <div className="max-h-64 overflow-y-auto border border-gray-700 rounded-lg">
                      <table className="w-full text-xs">
                        <thead className="sticky top-0 bg-gray-800">
                          <tr className="text-gray-400 border-b border-gray-700">
                            <th className="w-8 p-2 text-center">
                              <input
                                type="checkbox"
                                checked={
                                  devices.length > 0 &&
                                  selectedIps.size === devices.length
                                }
                                onChange={() =>
                                  selectedIps.size === devices.length
                                    ? deselectAll()
                                    : selectAll()
                                }
                                className="accent-purple-500"
                              />
                            </th>
                            <th className="p-2 text-left font-medium">IP</th>
                            <th className="p-2 text-left font-medium">
                              Hostname
                            </th>
                            <th className="p-2 text-left font-medium">MAC</th>
                            <th className="p-2 text-left font-medium">
                              Vendor
                            </th>
                          </tr>
                        </thead>
                        <tbody>
                          {devices.map((dev) => (
                            <tr
                              key={dev.ip}
                              onClick={() => toggleDevice(dev.ip)}
                              className={`border-b border-gray-800 cursor-pointer transition-colors hover:bg-gray-800/50 ${
                                selectedIps.has(dev.ip)
                                  ? 'bg-purple-500/10'
                                  : ''
                              }`}
                            >
                              <td className="p-2 text-center">
                                <input
                                  type="checkbox"
                                  checked={selectedIps.has(dev.ip)}
                                  onChange={() => toggleDevice(dev.ip)}
                                  className="accent-purple-500"
                                />
                              </td>
                              <td className="p-2 font-mono text-gray-200">
                                {dev.ip}
                              </td>
                              <td className="p-2 text-gray-300">
                                {dev.hostname || (
                                  <span className="text-gray-600">—</span>
                                )}
                              </td>
                              <td className="p-2 font-mono text-gray-400">
                                {dev.mac || (
                                  <span className="text-gray-600">—</span>
                                )}
                              </td>
                              <td className="p-2">
                                <span className="flex items-center gap-1.5">
                                  {getDeviceIcon(dev)}
                                  <span className="text-gray-300">
                                    {dev.vendor || (
                                      <span className="text-gray-600">
                                        Unknown
                                      </span>
                                    )}
                                  </span>
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                )}

                {devices.length === 0 && !scanning && !scanAttempted && (
                  <div className="text-center py-6 text-gray-500 text-sm">
                    <Search size={28} className="mx-auto mb-2 opacity-30" />
                    <p>
                      Click{' '}
                      <strong className="text-gray-400">Scan Network</strong>{' '}
                      to discover devices on your local subnet.
                    </p>
                  </div>
                )}
                {devices.length === 0 && !scanning && scanAttempted && (
                  <div className="text-center py-6 text-gray-500 text-sm">
                    <Search size={28} className="mx-auto mb-2 opacity-30" />
                    <p className="text-gray-400">
                      No devices found on the network.
                    </p>
                    <p className="text-gray-600 mt-1">
                      Make sure Npcap is installed and you're on the same
                      subnet. Retry scanning or add IPs manually above.
                    </p>
                  </div>
                )}
                {scanning && (
                  <div className="text-center py-6 text-gray-500 text-sm">
                    <div className="animate-spin inline-block w-6 h-6 border-2 border-purple-500 border-t-transparent rounded-full mb-2" />
                    <p>Scanning network, please wait...</p>
                  </div>
                )}
              </div>

              {/* Start button */}
              <div className="flex items-center justify-between mt-4">
                <span className="text-xs text-gray-400">
                  {selectedIps.size > 0
                    ? `${selectedIps.size} device${selectedIps.size !== 1 ? 's' : ''} selected`
                    : 'Add an IP manually or scan to select targets'}
                </span>
                <button
                  onClick={handleStart}
                  disabled={loading || selectedIps.size === 0}
                  className="flex items-center gap-2 px-5 py-2.5 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-lg transition-colors"
                >
                  <Play size={16} />
                  {loading
                    ? 'Starting...'
                    : `Start Interception (${selectedIps.size})`}
                </button>
              </div>
            </div>
          </>
        )}

        {/* ── Stealth: manual proxy (no ARP spoofing) ───────────────────── */}
        <div className="p-4 rounded-lg border border-gray-800 bg-gray-900/50 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <Shield size={14} className="text-green-400" />
            <h3 className="text-sm font-semibold text-gray-200">
              Stealth Mode — Manual Proxy
            </h3>
          </div>
          <p className="text-xs text-gray-400 mb-3 leading-relaxed">
            Devices on the network can flag <strong>ARP spoofing</strong> and
            show a "suspicious network activity" or "untrusted connection"
            alert, which also makes them drop the connection so nothing gets
            intercepted. Configuring the target's <em>Wi-Fi proxy</em> manually
            avoids that — no ARP, no gateway takeover. This reduces suspicious
            network-activity alerts and works on phones, tablets, desktops and
            IoT devices that let you set a manual proxy. It is not a guarantee
            of stealth: Wi-Fi/OS stacks may still detect unusual TLS or report
            an untrusted certificate.
          </p>
          <ol className="text-xs text-gray-400 space-y-1.5 list-decimal list-inside mb-3">
            <li>
              Download the <strong>Nyx CA</strong> certificate (button below)
              and install it on the target device (Settings → Security →
              Encryption &amp; Credentials → Install a certificate → CA).
            </li>
            <li>
              On the target phone open{' '}
              <span className="text-gray-200 font-mono">
                Wi-Fi Settings → your network → Modify → Advanced → Proxy
              </span>{' '}
              and set{' '}
              <span className="text-gray-100 font-mono">
                Manual / {status?.local_ip || 'NYX-IP'}:{status?.proxy_port ?? 8080}
              </span>
            </li>
            <li>
              Traffic is captured without ARP spoofing. Start the proxy and
              intercept from the{' '}
              <span className="text-purple-300">Proxy</span> tab instead of
              clicking "Start Interception" below.
            </li>
          </ol>
          <p className="text-xs text-green-400 mb-3">
            Proxy endpoint:{" "}
            <span className="font-mono">
              {status?.local_ip || '…'}:{status?.proxy_port ?? 8080}
            </span>
          </p>
          <a
            href="/api/ca-certificate"
            download
            className="inline-flex items-center gap-2 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium rounded-lg transition-colors border border-gray-700"
          >
            <Download size={12} />
            Download CA (install on target)
          </a>
        </div>

        {/* ── Deploy: remote system command generator ───────────────────── */}
        <div className="mb-6">
          <DeployBox
            host={status?.proxy_host || status?.local_ip || ''}
            proxyPort={status?.proxy_port ?? 8080}
            caPort={18081}
          />
        </div>

        {/* ── How it works ────────────────────────────────────────────────── */}
        <div className="p-4 rounded-lg border border-gray-800 bg-gray-900/30">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
            How it works
          </h3>
          <div className="text-xs text-gray-500 space-y-2 leading-relaxed">
            <p>
              <strong className="text-gray-300">1. Network Scan</strong> —
              Click "Scan Network" to discover all devices on your local subnet.
              Devices are detected via ARP and shown with IP, hostname, MAC
              address, and vendor (if known).{' '}
              <em className="text-gray-600">
                Results are saved — you can switch tabs and come back without
                losing them.
              </em>
            </p>
            <p>
              <strong className="text-gray-300">2. Select Targets</strong> —
              Check the devices you want to intercept. TVs, smart speakers, and
              other IoT devices can be skipped.
            </p>
            <p>
              <strong className="text-gray-300">3. ARP Spoofing</strong> — Nyx
              sends fake ARP packets to each selected target, impersonating the
              gateway. Each target sends all its traffic through Nyx. Intervals
              are randomised to reduce IDS detection.
            </p>
            <p>
              <strong className="text-gray-300">
                4. Transparent Proxy + DNS Spoofing
              </strong>{' '}
              — Traffic is forwarded to the real destination while being logged.
              Optional DNS spoofing intercepts all DNS queries (resolves to Nyx
              IP).
            </p>
            <p>
              <strong className="text-gray-300">5. Restoration</strong> — When
              stopped, correct ARP packets (×3 for reliability) restore the
              original gateway mapping for each target.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

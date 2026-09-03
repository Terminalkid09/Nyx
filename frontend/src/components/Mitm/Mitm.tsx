import { useEffect, useCallback, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  getMitmStatus,
  startMitm,
  stopMitm,
  setTlsMitm,
  setQuicMode,
  addUdpRule,
  removeUdpRule,
  clearUdpPolicy,
  scanNetwork,
  removeCaFromHost,
  MitmStatus,
  NetworkDevice,
  UdpRule,
} from '../../api/endpoints/mitm'
import { useMitmStore } from '../../store/useMitmStore'
import { useSessionStore } from '../../store/useSessionStore'
import { DeployBox } from './DeployBox'
import { DhcpStatusPanel } from './DhcpStatusPanel'
import { ActivityMonitor } from './ActivityMonitor'
import { TrafficDiagnosticsPanel } from './TrafficDiagnosticsPanel'
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
  AlertTriangle,
} from 'lucide-react'

const statusColor = (ok: boolean) => (ok ? 'text-green-400' : 'text-red-400')
const bgStatus = (ok: boolean) =>
  ok
    ? 'bg-green-500/10 border-green-500/30'
    : 'bg-red-500/10 border-red-500/30'

const scrollToStealth = () => {
  document.getElementById('stealth')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

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
  const [tlsSaving, setTlsSaving] = useState(false)
  const [quicSaving, setQuicSaving] = useState(false)
  // UDP rules editor (drop/pass forwarded target UDP at the WinDivert layer).
  const [udpRules, setUdpRules] = useState<UdpRule[]>([])
  const [udpMatched, setUdpMatched] = useState(0)
  const [udpDropped, setUdpDropped] = useState(0)
  const [udpTarget, setUdpTarget] = useState('')
  const [udpPort, setUdpPort] = useState('')
  const [udpAction, setUdpAction] = useState<'drop' | 'pass'>('drop')
  const [udpSaving, setUdpSaving] = useState(false)

  // CA removal from THIS PC (post-test cleanup)
  const [caRemoving, setCaRemoving] = useState(false)
  const [caRemoveMsg, setCaRemoveMsg] = useState<string | null>(null)

  // All persistent UI state comes from the store
  const {
    devices,
    selectedIps,
    gatewayIp,
    enableDns,
    spoofMethod,
    arpMode,
    enableWifiAp,
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
    setSpoofMethod,
    setArpMode,
    setEnableWifiAp,
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
      setStatus(s)
      if (s.gateway_ip) setGatewayIp(s.gateway_ip)
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

  // Sync the UDP rules editor with the status poll (3s) — rules + counters
  // stay live without extra requests after every mutation.
  useEffect(() => {
    setUdpRules(status?.udp_policy?.rules ?? [])
    setUdpMatched(status?.udp_policy?.matched ?? 0)
    setUdpDropped(status?.udp_policy?.dropped ?? 0)
  }, [status?.udp_policy])

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

  const errText = (e: any, fallback: string) => {
    const timedOut =
      e?.code === 'ECONNABORTED' || /timeout/i.test(e?.message || '')
    if (timedOut)
      return (
        `${fallback} timed out after 120s. The backend is still working — ` +
        `wait a few seconds and check the status. If it was a Stop, the ` +
        `session is being torn down in the background and will finish on its own.`
      )
    return e?.response?.data?.detail || e?.message || fallback
  }

  const handleStart = async () => {
    if (selectedIps.size === 0) return
    setLoading(true)
    setError(null)
    try {
      const res = await startMitm({
        target_ips: Array.from(selectedIps),
        gateway_ip: gatewayIp,
        enable_dns_spoof: enableDns,
        spoof_method: spoofMethod as 'auto' | 'arp' | 'dhcp',
        arp_mode: arpMode as 'reactive' | 'active',
        enable_wifi_ap: enableWifiAp,
      })
      // MITM traffic is stamped with a dedicated MITM Session (backend).
      // Switch the active session to it so the Proxy tab shows the captured
      // traffic (and the WebSocket filter matches) — regardless of which
      // session the UI had persisted before.
      if (res?.session_id) {
        useSessionStore.getState().activateSession(res.session_id).catch(() => {})
        useSessionStore.getState().fetchSessions().catch(() => {})
      }
      await fetchStatus()
    } catch (e: any) {
      setError(errText(e, 'Failed to start MITM'))
    } finally {
      setLoading(false)
    }
  }

  const handleStop = async () => {
    setLoading(true)
    setError(null)
    try {
      await stopMitm()
      // Optimistically show the inactive panel, then let the 3s poll confirm
      // the backend really tore everything down.
      setStatus({
        active: false,
        arp_spoofing: false,
        dns_spoofing: false,
        target_ips: [],
        gateway_ip: null,
        admin_mode: !!(status?.admin_mode),
      })
      await fetchStatus()
    } catch (e: any) {
      setError(errText(e, 'Failed to stop MITM'))
      await fetchStatus()
    } finally {
      setLoading(false)
    }
  }

  const handleManualKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') addManualIp()
  }

  const handleSetTls = async (active: boolean) => {
    setTlsSaving(true)
    setError(null)
    try {
      const res = await setTlsMitm(active)
      setStatus((s) => s ? { ...s, tls_mitm: res.tls_mitm } : null)
      await fetchStatus()
    } catch (e: any) {
      setError(
        e.response?.data?.detail || e.message || 'Failed to toggle HTTPS decryption'
      )
    } finally {
      setTlsSaving(false)
    }
  }

  const handleSetQuic = async (mode: 'drop' | 'allow') => {
    setQuicSaving(true)
    setError(null)
    try {
      const res = await setQuicMode(mode)
      setStatus((s) => s ? { ...s, quic_mode: res.mode } : null)
      await fetchStatus()
    } catch (e: any) {
      setError(
        e.response?.data?.detail || e.message || 'Failed to change QUIC handling'
      )
    } finally {
      setQuicSaving(false)
    }
  }

  const handleAddUdpRule = async () => {
    const target = udpTarget.trim()
    if (!target) {
      setError('Enter a target IP for the UDP rule')
      return
    }
    const port = udpPort.trim() ? Number(udpPort) : null
    if (port !== null && (Number.isNaN(port) || port < 0 || port > 65535)) {
      setError('UDP port must be 0-65535, or leave blank for all ports')
      return
    }
    setUdpSaving(true)
    setError(null)
    try {
      await addUdpRule({ target, dst_port: port, action: udpAction })
      setUdpTarget('')
      setUdpPort('')
      await fetchStatus()
    } catch (e: any) {
      setError(e.response?.data?.detail || e.message || 'Failed to add UDP rule')
    } finally {
      setUdpSaving(false)
    }
  }

  const handleRemoveUdpRule = async (index: number) => {
    setUdpSaving(true)
    setError(null)
    try {
      await removeUdpRule(index)
      await fetchStatus()
    } catch (e: any) {
      setError(e.response?.data?.detail || e.message || 'Failed to remove UDP rule')
    } finally {
      setUdpSaving(false)
    }
  }

  const handleClearUdpRules = async () => {
    setUdpSaving(true)
    setError(null)
    try {
      await clearUdpPolicy()
      await fetchStatus()
    } catch (e: any) {
      setError(e.response?.data?.detail || e.message || 'Failed to clear UDP rules')
    } finally {
      setUdpSaving(false)
    }
  }

  const handleRemoveCa = async () => {
    setCaRemoving(true)
    setCaRemoveMsg(null)
    try {
      const res = await removeCaFromHost()
      setCaRemoveMsg(res.message)
    } catch (e: any) {
      setCaRemoveMsg(e.response?.data?.detail || e.message || 'Failed to remove the CA')
    } finally {
      setCaRemoving(false)
    }
  }

  const isActive = status?.active ?? false
  const transportReady = status?.transport_ready ?? status?.redirect_active ?? false
  const targetIps = status?.target_ips ?? []
  const capturedFlows = status?.captured_flows ?? 0
  const tlsEnabled = status?.tls_mitm !== false
  const quicBlockMode = status?.quic_mode ?? 'drop'
  const lastTrafficSeen = status?.last_traffic_seen
  const trafficLastTs = lastTrafficSeen ? new Date(lastTrafficSeen).getTime() : 0
  // "Idle" = redirect/transport is up but no flow has been captured in the
  // last 30s (or none ever). Used to distinguish "fine but quiet" from
  // "something is wrong" without claiming ACTIVE proves traffic works.
  const idleMs = trafficLastTs ? Math.max(0, timeNow - trafficLastTs) : (isActive ? Number.MAX_SAFE_INTEGER : 0)
  const trafficIdle = isActive && (capturedFlows === 0 || idleMs > 30000)
  // Packets from the target ARE reaching Nyx (WinDivert counter), but no flow
  // has been decrypted: interception works, the TLS handshake is being
  // rejected (CA not installed on the target / QUIC / pinning). The UI must
  // say so instead of the generic "no traffic seen".
  const packetsForwarded = status?.forwarded_packets ?? 0
  const forwardedLastSeen = status?.forwarded_last_seen
  const forwardedLastTs = forwardedLastSeen ? new Date(forwardedLastSeen).getTime() : 0
  const interceptingButNoFlows = isActive && packetsForwarded > 0 && capturedFlows === 0
  const tlsFailures = status?.tls_handshake_failures ?? 0
  const tlsFailedHosts = status?.tls_failed_hosts ?? []
  const trafficFlowing =
    isActive &&
    (capturedFlows > 0 ||
      (packetsForwarded > 0 && forwardedLastTs > 0 && timeNow - forwardedLastTs < 30000))
  // Transport degraded = interception "on" but traffic can't reach the
  // proxy automatically (WinDivert/pf failed) — the target phone would be
  // blackholed, so the UI must say so instead of showing ACTIVE.
  const transportDegraded = (status?.arp_spoofing || status?.dns_spoofing || status?.dhcp_spoofing) && !transportReady

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
            <div className="flex items-start justify-between gap-3">
              <span>{error}</span>
              {error.includes('Stealth Mode') && (
                <button
                  onClick={scrollToStealth}
                  className="shrink-0 text-xs px-3 py-1.5 bg-red-600/20 hover:bg-red-600/30 border border-red-500/30 text-red-300 rounded-lg transition-colors"
                >
                  Go to Stealth Mode
                </button>
              )}
            </div>
          </div>
        )}

        {/* ── HTTPS decryption disabled banner ─────────────────────────────── */}
        {status?.tls_mitm === false && (
          <div className="mb-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-sm flex items-start gap-2">
            <AlertTriangle size={16} className="shrink-0 mt-0.5" />
            <div>
              <strong>HTTPS decryption is OFF.</strong> HTTPS traffic is
              tunnelled untouched (plain HTTP proxy). To decrypt it: enable
              the <em>Decrypt HTTPS</em> toggle below and make sure the Nyx CA
              is trusted — install it on this machine (Download CA → import in
              the system store, then restart the proxy) and on the target
              device (Deploy Command) to browse without certificate warnings.
            </div>
          </div>
        )}

        {/* ── Status Cards ────────────────────────────────────────────────── */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div className={`p-4 rounded-lg border ${transportDegraded ? bgStatus(false) : bgStatus(isActive)}`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-300">Status</span>
              <span
                className={`text-sm font-bold ${
                  transportDegraded
                    ? 'text-amber-400'
                    : statusColor(isActive)
                }`}
              >
                {transportDegraded ? 'DEGRADED' : isActive ? 'ACTIVE' : 'INACTIVE'}
              </span>
            </div>
            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-gray-400">MITM transport</span>
                <span className={transportDegraded ? 'text-amber-400' : statusColor(transportReady)}>
                  {transportReady ? 'UP' : transportDegraded ? 'BLOCKED' : 'DOWN'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">ARP Spoofing</span>
                <span className={statusColor(status?.arp_spoofing ?? false)}>
                  {status?.arp_spoofing ? 'ON' : 'OFF'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">DHCP Spoofing</span>
                <span className={statusColor(status?.dhcp_spoofing ?? false)}>
                  {status?.dhcp_spoofing ? 'ON' : 'OFF'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">DHCP offers sent</span>
                <span className="text-gray-200 font-mono">
                  {status?.dhcp_offers ?? 0}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Lease requests (accepted)</span>
                <span className="text-gray-200 font-mono">
                  {status?.dhcp_lease_requests ?? 0}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Target packets captured</span>
                <span className="text-gray-200 font-mono">
                  {status?.forwarded_packets ?? 0}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">DNS Spoofing</span>
                <span className={statusColor(status?.dns_spoofing ?? false)}>
                  {status?.dns_spoofing ? 'ON' : 'OFF'}
                </span>
              </div>
              {status?.dns_spoof_error && (
                <div className="text-[10px] text-red-400 bg-red-500/10 rounded p-1.5">
                  DNS spoofing failed: {status.dns_spoof_error}
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-gray-400">HTTPS decryption</span>
                <span className={statusColor(status?.tls_mitm ?? true)}>
                  {status?.tls_mitm === false ? 'OFF — passthrough' : 'ON'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Flows captured</span>
                <span className={statusColor(capturedFlows > 0)}>
                  {capturedFlows > 0 ? capturedFlows : '0'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">TLS rejected by target</span>
                <span className={statusColor(tlsFailures === 0)}>
                  {tlsFailures > 0 ? `${tlsFailures} handshake${tlsFailures === 1 ? '' : 's'}` : 'none'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Last traffic seen</span>
                <span className={statusColor(trafficFlowing)}>
                  {lastTrafficSeen
                    ? new Date(trafficLastTs).toLocaleTimeString()
                    : isActive
                      ? forwardedLastSeen
                        ? `${new Date(forwardedLastTs).toLocaleTimeString()} (packets only)`
                        : 'never'
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

        {/* ── Transport Degraded Warning ──────────────────────────────────── */}
        {transportDegraded && (
          <div className="p-5 rounded-lg border border-red-500/30 bg-red-500/5 mb-6">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle size={16} className="text-red-400" />
              <h2 className="text-sm font-semibold text-red-400">
                Transport not ready — targets will NOT reach the proxy
              </h2>
            </div>
            <p className="text-xs text-gray-300 mb-2">
              ARP/DHCP/DNS spoofing is running but the transparent redirect
              (WinDivert / pf) did not come up. Traffic from the target phone
              will NOT be seen by Nyx — the device may even lose internet
              access. Fix the transport (run Nyx as Administrator) or intercept
              with Stealth Mode instead.
            </p>
            <button
              onClick={() => scrollToStealth()}
              className="text-xs px-3 py-1.5 bg-red-600/20 hover:bg-red-600/30 border border-red-500/30 text-red-300 rounded-lg transition-colors"
            >
              Go to Stealth Mode
            </button>
          </div>
        )}

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
                Browse to any{' '}
                <span className="text-gray-200">http://</span> or{' '}
                <span className="text-gray-200">https://</span> site on the
                target device to see captured requests in the{' '}
                <span className="text-gray-200">Proxy</span> tab. HTTPS is
                decrypted with the Nyx CA — install it on the target (Deploy
                Command) to suppress certificate warnings.
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
              <DhcpStatusPanel status={status} />
              {trafficIdle && (
                <TrafficDiagnosticsPanel
                  interceptingButNoFlows={interceptingButNoFlows}
                  packetsForwarded={packetsForwarded}
                  tlsFailures={tlsFailures}
                  tlsFailedHosts={tlsFailedHosts}
                  lastTrafficSeen={lastTrafficSeen}
                />
              )}
            </div>

            <div className="flex flex-wrap gap-3">
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
              <a
                href="/api/requests/export/har"
                download
                className="flex items-center gap-2 px-5 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-sm font-medium rounded-lg transition-colors border border-gray-700"
                title="Export the captured session as HAR (opens in DevTools/Charles)"
              >
                <Download size={16} />
                Export HAR
              </a>
              <button
                onClick={handleRemoveCa}
                disabled={caRemoving}
                className="flex items-center gap-2 px-5 py-2.5 bg-gray-800 hover:bg-red-900/50 disabled:bg-gray-700 text-gray-200 text-sm font-medium rounded-lg transition-colors border border-gray-700"
                title="Remove the Nyx CA from THIS PC's trust store (post-test cleanup)"
              >
                {caRemoving ? 'Removing...' : 'Remove CA (this PC)'}
              </button>
            </div>

            {/* Live per-target activity (SNI + HTTP, works without the CA) */}
            <ActivityMonitor activity={status?.activity ?? []} />
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

                {/* Gateway IP — same size as Manual Target IP */}
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
                  <p className="text-[10px] text-gray-500 mt-1">
                    Your router IP — auto-detected from the network scan, edit
                    if needed
                  </p>
                </div>
              </div>

              {/* Options: DNS spoof / spoofing method / HTTPS decryption */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
                {/* DNS Spoof toggle */}
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">
                    DNS Spoof
                  </label>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setEnableDns(true)}
                      className={`flex-1 px-3 py-2 text-xs rounded font-medium transition-colors ${
                        enableDns
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-800 text-gray-400'
                      }`}
                    >
                      ON
                    </button>
                    <button
                      onClick={() => setEnableDns(false)}
                      className={`flex-1 px-3 py-2 text-xs rounded font-medium transition-colors ${
                        !enableDns
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-800 text-gray-400'
                      }`}
                    >
                      OFF
                    </button>
                  </div>
                  <p className="text-[10px] text-gray-500 mt-1">
                    Off by default — transparent mode already captures traffic
                  </p>
                </div>

                {/* Spoofing method selector */}
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">
                    Spoofing
                  </label>
                  <div className="flex gap-1.5">
                    {(['auto', 'arp', 'dhcp'] as const).map((m) => (
                      <button
                        key={m}
                        onClick={() => setSpoofMethod(m)}
                        className={`flex-1 px-2.5 py-2 text-xs rounded font-medium transition-colors ${
                          spoofMethod === m
                            ? 'bg-purple-600 text-white'
                            : 'bg-gray-800 text-gray-400'
                        }`}
                        title={
                          m === 'auto'
                            ? 'DHCP first (stealth, no alert) — automatic ARP fallback if DHCP does not convert within ~20s'
                            : m === 'arp'
                              ? 'ARP spoofing — immediate, may trigger a "suspicious network" alert on the target'
                              : 'DHCP spoofing only — stealthy (no alert), target must reconnect Wi-Fi once'
                        }
                      >
                        {m === 'auto' ? 'Auto' : m.toUpperCase()}
                      </button>
                    ))}
                  </div>
                  <p className="text-[10px] text-gray-500 mt-1">
                    Auto = DHCP first (no alert) → automatic ARP fallback
                  </p>
                </div>

                {/* ARP poisoning mode — stealth selector */}
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">
                    ARP Mode
                  </label>
                  <div className="flex gap-1.5">
                    {(['reactive', 'active'] as const).map((m) => (
                      <button
                        key={m}
                        onClick={() => setArpMode(m)}
                        className={`flex-1 px-2.5 py-2 text-xs rounded font-medium transition-colors ${
                          arpMode === m
                            ? 'bg-purple-600 text-white'
                            : 'bg-gray-800 text-gray-400'
                        }`}
                        title={
                          m === 'reactive'
                            ? 'Stealth: answer only when the target asks who the gateway is. Looks like normal ARP — much harder for Samsung/Android to detect.'
                            : 'Active: flood the target with spoofed replies every ~3s. Reliable but Samsung/Android flag this as suspicious activity.'
                        }
                      >
                        {m === 'reactive' ? 'Stealth (react)' : 'Active (flood)'}
                      </button>
                    ))}
                  </div>
                  <p className="text-[10px] text-gray-500 mt-1">
                    Stealth = answer only when asked — best against modern phones
                  </p>
                </div>

                {/* WiFi AP mode — the ultimate bypass */}
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">
                    WiFi AP Mode (zero detection)
                  </label>
                  <div className="flex gap-1.5">
                    <button
                      onClick={() => setEnableWifiAp(true)}
                      className={`flex-1 px-3 py-2 text-xs rounded font-medium transition-colors ${
                        enableWifiAp
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-800 text-gray-400'
                      }`}
                    >
                      ON
                    </button>
                    <button
                      onClick={() => setEnableWifiAp(false)}
                      className={`flex-1 px-3 py-2 text-xs rounded font-medium transition-colors ${
                        !enableWifiAp
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-800 text-gray-400'
                      }`}
                    >
                      OFF
                    </button>
                  </div>
                  <p className="text-[10px] text-gray-500 mt-1">
                    Turns Nyx into a rogue AP — the target connects to you, you
                    ARE the gateway. Zero spoofing, zero detection. Requires
                    driver support.
                  </p>
                </div>

                {/* Decrypt HTTPS (TLS MITM) toggle — live, no proxy restart */}
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">
                    Decrypt HTTPS
                  </label>
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleSetTls(true)}
                      disabled={tlsSaving}
                      className={`flex-1 px-3 py-2 text-xs rounded font-medium transition-colors ${
                        tlsEnabled
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-800 text-gray-400'
                      }`}
                    >
                      ON
                    </button>
                    <button
                      onClick={() => handleSetTls(false)}
                      disabled={tlsSaving}
                      className={`flex-1 px-3 py-2 text-xs rounded font-medium transition-colors ${
                        !tlsEnabled
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-800 text-gray-400'
                      }`}
                    >
                      OFF
                    </button>
                  </div>
                  <p className="text-[10px] text-gray-500 mt-1">
                    Requires the Nyx CA on the target
                  </p>
                </div>

                {/* QUIC handling toggle — live, no proxy restart */}
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">
                    Force HTTPS fallback (QUIC)
                  </label>
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleSetQuic('drop')}
                      disabled={quicSaving}
                      className={`flex-1 px-3 py-2 text-xs rounded font-medium transition-colors ${
                        quicBlockMode === 'drop'
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-800 text-gray-400'
                      }`}
                    >
                      ON
                    </button>
                    <button
                      onClick={() => handleSetQuic('allow')}
                      disabled={quicSaving}
                      className={`flex-1 px-3 py-2 text-xs rounded font-medium transition-colors ${
                        quicBlockMode === 'allow'
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-800 text-gray-400'
                      }`}
                    >
                      OFF
                    </button>
                  </div>
                  <p className="text-[10px] text-gray-500 mt-1">
                    ON drops the target's UDP/443 so browsers fall back to
                    interceptable HTTPS; OFF lets QUIC pass through unread.
                  </p>
                </div>

                {/* UDP rules editor — drop/pass forwarded target UDP */}
                <div className="mt-4 pt-4 border-t border-gray-700">
                  <label className="block text-xs text-gray-400 mb-1.5">
                    UDP rules (drop / pass target UDP traffic)
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={udpTarget}
                      onChange={(e) => setUdpTarget(e.target.value)}
                      placeholder="Target IP"
                      className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono focus:outline-none focus:ring-1 focus:ring-purple-500"
                    />
                    <input
                      type="text"
                      value={udpPort}
                      onChange={(e) => setUdpPort(e.target.value)}
                      placeholder="Port"
                      className="w-20 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono focus:outline-none focus:ring-1 focus:ring-purple-500"
                    />
                    <select
                      value={udpAction}
                      onChange={(e) => setUdpAction(e.target.value as 'drop' | 'pass')}
                      className="bg-gray-800 border border-gray-700 rounded px-2 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-purple-500"
                    >
                      <option value="drop">Drop</option>
                      <option value="pass">Pass</option>
                    </select>
                    <button
                      onClick={handleAddUdpRule}
                      disabled={udpSaving}
                      className="px-3 py-2 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:text-gray-500 text-gray-200 text-sm rounded-lg transition-colors"
                    >
                      + Add
                    </button>
                  </div>
                  <p className="text-[10px] text-gray-500 mt-1">
                    Drop silently kills matching UDP flows from the target;
                    Pass explicitly allows them (blank port = all ports).
                  </p>

                  {udpRules.length > 0 && (
                    <div className="mt-2 space-y-1">
                      {udpRules.map((r, i) => (
                        <div
                          key={`${r.target}-${r.dst_port ?? '*'}-${r.action}-${i}`}
                          className="flex items-center justify-between px-2 py-1 rounded bg-gray-800/60 border border-gray-700/60"
                        >
                          <span className="font-mono text-xs text-gray-300">
                            {r.target}:{r.dst_port ?? '*'}{' '}
                            <span
                              className={r.action === 'drop' ? 'text-red-400' : 'text-emerald-400'}
                            >
                              {r.action}
                            </span>
                          </span>
                          <button
                            onClick={() => handleRemoveUdpRule(i)}
                            disabled={udpSaving}
                            className="text-gray-500 hover:text-red-400 text-sm px-1 disabled:text-gray-700"
                          >
                            &times;
                          </button>
                        </div>
                      ))}
                      <div className="flex items-center justify-between pt-1">
                        <span className="text-[10px] text-gray-500">
                          matched {udpMatched} &middot; dropped {udpDropped}
                        </span>
                        <button
                          onClick={handleClearUdpRules}
                          disabled={udpSaving}
                          className="text-[10px] text-gray-500 hover:text-red-400 disabled:text-gray-700 transition-colors"
                        >
                          Clear all
                        </button>
                      </div>
                    </div>
                  )}
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
        <div id="stealth" className="p-4 rounded-lg border border-gray-800 bg-gray-900/50 mb-6">
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

        {/* ── CA uninstall (target + this PC) ───────────────────────────── */}
        <div className="p-4 rounded-lg border border-gray-800 bg-gray-900/50 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle size={14} className="text-amber-400" />
            <h3 className="text-sm font-semibold text-gray-200">
              Remove the CA when done
            </h3>
          </div>
          <p className="text-xs text-gray-400 mb-3 leading-relaxed">
            Trusting the Nyx CA disables TLS integrity checks for it. Remove it
            from every device that installed it as soon as testing is over.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
            <div className="text-xs text-gray-400 space-y-1.5">
              <p className="text-gray-300 font-medium">Android</p>
              <p>Settings → Lock screen &amp; security → Certificate management → Remove → select the Nyx/mitmproxy entry</p>
            </div>
            <div className="text-xs text-gray-400 space-y-1.5">
              <p className="text-gray-300 font-medium">iOS / iPadOS</p>
              <p>Settings → General → VPN &amp; Device Management → delete the Nyx profile; then Settings → General → About → Certificate Trust Settings → disable Nyx CA</p>
            </div>
            <div className="text-xs text-gray-400 space-y-1.5">
              <p className="text-gray-300 font-medium">Windows / macOS</p>
              <p>Windows: certmgr.msc → Trusted Root → remove the mitmproxy/Nyx entry. macOS: Keychain Access → System → delete the Nyx entry.</p>
            </div>
            <div className="text-xs text-gray-400 space-y-1.5">
              <p className="text-gray-300 font-medium">This PC</p>
              <button
                onClick={handleRemoveCa}
                disabled={caRemoving}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 hover:bg-red-900/50 disabled:bg-gray-700 text-gray-200 text-xs font-medium rounded-lg transition-colors border border-gray-700"
              >
                {caRemoving ? 'Removing...' : 'Remove CA from this PC'}
              </button>
              {caRemoveMsg && (
                <p className="text-[11px] text-gray-400 mt-1.5">{caRemoveMsg}</p>
              )}
            </div>
          </div>
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
              <strong className="text-gray-300">3. Spoofing (Auto)</strong> —
              By default Nyx uses{' '}
              <strong className="text-gray-300">DHCP spoofing</strong>: the
              target is assigned Nyx as its gateway legitimately, so phones do
              NOT show the "suspicious network activity" alert (no forged ARP,
              gateway MAC never conflicts). The target must reconnect to Wi-Fi
              once to receive the lease. If DHCP can't start, Nyx falls back to
              classic ARP spoofing (immediate, but phones may flag it).
            </p>
            <p>
              <strong className="text-gray-300">4. Transparent Proxy</strong>{' '}
              — Traffic is forwarded to the real destination while being logged.
              DNS spoofing is OFF by default: with transparent interception it
              is unnecessary and can break the target's connectivity.
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

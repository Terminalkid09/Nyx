import { useState, useEffect, useCallback, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { Activity, Play, StopCircle, Download, Radio, Waves, Globe, GitBranch, RefreshCw, ChevronRight, ChevronDown, X, ListTree, ArrowRightCircle, AlertTriangle } from 'lucide-react'
import { apiClient } from '../../api/client'

interface NetStats {
  pps: number
  bps: number
  active_flows: number
  tcp_streams: number
  udp_flows: number
  bytes_total: number
  packets_total: number
  errors: number
  by_protocol: Record<string, number>
  by_port: Record<string, number>
  timestamp: string
}

interface NetStatus {
  running: boolean
  interface: string
  bpf_filter: string
  pcap_path: string | null
  stats: NetStats
  tcp_streams: number
  udp_flows: number
  packets_buffered: number
  frames_buffered: number
  /** Watchdog rebinds this session (adaptive capture). Absent on older backends. */
  interface_changes?: number
  /** Aggregated QUIC connections (one row per DCID). Absent on older backends. */
  quic_connections?: number
}

interface CaptureInterface {
  name: string
  is_up: boolean
  is_loopback: boolean
  ipv4: string[]
  is_default: boolean
}

interface PacketSummary {
  /** Monotonic id from the engine — key for the detail endpoint. */
  seq?: number
  timestamp: string
  length: number
  proto: string
  src?: string
  dst?: string
  sport?: number
  dport?: number
  icmp_type?: number
  eth_src?: string
  eth_dst?: string
}

interface PacketDetailLayer {
  name: string
  /** Field value: display string, or {repr, raw} for numeric fields. */
  fields: Record<string, string | { repr: string; raw: number }>
}

interface PacketDetail {
  seq: number
  timestamp: string
  length: number
  sniffed_on: string
  proto: string
  layers: PacketDetailLayer[]
  hexdump: string
}

interface FrameEntry {
  frame_type: string
  timestamp: string
  data: Record<string, any>
  five_tuple: any
}

interface StreamFrame {
  frame_type: string
  timestamp: string
  data: Record<string, any>
}

interface StreamSummary {
  stream_id: string
  five_tuple: {
    src_ip: string
    dst_ip: string
    src_port: number
    dst_port: number
    protocol: number
  }
  transport: string
  frame_count: number
  start_time: string
  last_seen: string
  bytes_total: number
  sni: string | null
  link: { type: string; protocol: string } | null
}

/** One aggregated QUIC connection (from GET /api/network/quic). */
interface QuicConnection {
  conn_id: string
  dcid: string | null
  version: number | null
  packet_count: number
  packet_types: Record<string, number>
  first_seen: string | null
  last_seen: string | null
  five_tuple: {
    src_ip?: string
    dst_ip?: string
    src_port?: number
    dst_port?: number
  } | null
}

/** The remote endpoint of a QUIC connection: whichever side speaks 443/8443. */
function quicPeer(ft: QuicConnection['five_tuple']): string {
  if (!ft) return '—'
  if (ft.dst_port === 443 || ft.dst_port === 8443) return `${ft.dst_ip}:${ft.dst_port}`
  if (ft.src_port === 443 || ft.src_port === 8443) return `${ft.src_ip}:${ft.src_port}`
  return ft.dst_ip ? `${ft.dst_ip}:${ft.dst_port ?? '?'}` : '—'
}

function quicVersion(v: number | null): string {
  if (v === 1) return 'v1'
  if (v === 2) return 'v2'
  if (v == null) return '—'
  return `0x${v.toString(16)}`
}

// ── Capture-visibility heuristics ───────────────────────────────────────────
// Windows names virtual/VPN adapters in fairly recognizable ways (McAfee_VPN,
// WireGuard Tunnel, TAP-Windows, Npcap Loopback, ...). The name test is a
// heuristic — the interfaces list's is_loopback flag is authoritative when
// present, so both are used.
const VIRTUAL_IFACE_RE =
  /vpn|wireguard|wintun|tunnel|tun\d|tap[- ]|virtual|loopback|npcap|teredo|isatap|bluetooth|vmware|virtualbox|hyper-v|vethernet|tailscale|zerotier|docker|wi-?fi direct/i

function isVirtualInterface(name: string): boolean {
  return VIRTUAL_IFACE_RE.test(name)
}

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV6_RE = /^[0-9a-fA-F:]+$/

function isIpAddress(s: string): boolean {
  return IPV4_RE.test(s) || (s.includes(':') && IPV6_RE.test(s))
}

/** When the WHOLE expression is a single-host filter, return that IP.
 *  ("host 1.2.3.4", "ip host ...", "src/dst host ...", "src ip ...")
 *  Anything wider ("tcp or udp", "tcp port 443", ...) returns null. */
function singleHostBpf(bpf: string): string | null {
  const expr = bpf.trim().replace(/\s+/g, ' ')
  const m =
    expr.match(/^(?:ip6?\s+)?host\s+(\S+)$/i) ||
    expr.match(/^(?:src|dst)\s+(?:host|ip6?)\s+(\S+)$/i)
  if (m && isIpAddress(m[1])) return m[1]
  return null
}

function frameSummary(f: FrameEntry): string {
  const d = f.data || {}
  switch (f.frame_type) {
    case 'dns':
      return d.questions?.[0]?.name || d.answers?.[0]?.name || `DNS ${d.is_query ? 'query' : 'response'}`
    case 'dhcp':
      return `DHCP ${d.is_request ? 'request' : 'reply'}${d.message_type ? ` (type ${d.message_type})` : ''}`
    case 'arp':
      return `${d.psrc} → ${d.pdst} (${d.is_request ? 'who-has' : 'reply'})`
    case 'icmp':
      return `ICMP type ${d.type} code ${d.code}${d.seq != null ? ` seq=${d.seq}` : ''}`
    case 'quic':
      if (d.aggregated) {
        const types = Object.entries(d.packet_types || {})
          .map(([t, n]) => `${t}×${n}`)
          .join(' + ')
        return `QUIC conn ${String(d.dcid || d.conn_id || '?').slice(0, 8)}… · ${d.packet_count} packets${types ? ` (${types})` : ''}`
      }
      return `QUIC ${d.header_form}${d.packet_type ? ` ${d.packet_type}` : ''}${d.version ? ` v${d.version}` : ''}`
    case 'tls':
      return `TLS → ${d.sni || '?'}`
    case 'tcp_frame':
      return `TCP seq=${d.seq} len=${d.payload_length} ${d.is_client ? 'C→S' : 'S→C'}`
    case 'udp_packet':
      return `UDP len=${d.length}`
    default:
      return f.frame_type
  }
}

export function Network() {
  const [status, setStatus] = useState<NetStatus | null>(null)
  const [packets, setPackets] = useState<PacketSummary[]>([])
  const [frames, setFrames] = useState<FrameEntry[]>([])
  const [streams, setStreams] = useState<StreamSummary[]>([])
  // Aggregated QUIC connections (one row per DCID, from /api/network/quic).
  const [quicConns, setQuicConns] = useState<QuicConnection[]>([])
  const [showQuic, setShowQuic] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  // "auto" = backend resolves the interface that owns the default route and
  // keeps re-binding to it via the watchdog as the network changes.
  const [iface, setIface] = useState('auto')
  const [ifaces, setIfaces] = useState<CaptureInterface[]>([])
  const [ifaceListFailed, setIfaceListFailed] = useState(false)
  // Protocol checkboxes compose the BPF filter (all-on = the backend's
  // default "tcp or udp or arp or icmp"); the Advanced toggle swaps them
  // for a raw BPF expression for power users.
  const [protocols, setProtocols] = useState<Record<'tcp' | 'udp' | 'icmp' | 'arp', boolean>>({
    tcp: true, udp: true, icmp: true, arp: true,
  })
  const [advancedBpf, setAdvancedBpf] = useState(false)
  const [rawBpf, setRawBpf] = useState('')
  const [pcapPath, setPcapPath] = useState('')
  // Double-click packet detail (Wireshark-style layer tree + hexdump).
  const [detail, setDetail] = useState<PacketDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState('')
  const [openLayers, setOpenLayers] = useState<Set<number>>(new Set())
  // Double-click stream detail: the stream's frame-by-frame conversation.
  const [streamDetail, setStreamDetail] = useState<StreamSummary | null>(null)
  const [streamFrames, setStreamFrames] = useState<StreamFrame[]>([])
  // QUIC connection detail modal (double-click a 'quic' row in the frames
  // list) — no fetch needed: the frame row carries the summary, enriched
  // live from the quicConns registry when the connection is still active.
  const [quicDetail, setQuicDetail] = useState<{ summary: Record<string, any>; fiveTuple: any } | null>(null)
  const [streamDetailLoading, setStreamDetailLoading] = useState(false)
  const [streamDetailError, setStreamDetailError] = useState('')
  // Stop is slower than the default 30s client timeout (it tears down the
  // sniffer, tasks and pcap writer) — track it so the button gives feedback
  // and can't be double-clicked into two concurrent stop requests.
  const [stopping, setStopping] = useState(false)
  const navigate = useNavigate()

  const composedBpf = (
    (['tcp', 'udp', 'icmp', 'arp'] as const)
      .filter((p) => protocols[p])
      .join(' or ')
  )

  // Visibility warnings: (1) the capture is bound to a VPN/virtual adapter,
  // (2) the active filter excludes everything but one host. While running,
  // the source of truth is the status response; before starting, preview the
  // selected interface and the filter that WOULD be sent.
  const captureIface = status?.running ? status.interface : iface === 'auto' ? null : iface
  const activeBpfFilter = status?.running ? (status.bpf_filter || '') : advancedBpf ? rawBpf : composedBpf
  const ifaceEntry = ifaces.find((i) => i.name === captureIface)
  const isVirtualIface =
    captureIface != null && (ifaceEntry?.is_loopback || isVirtualInterface(captureIface))
  const singleHostIp = activeBpfFilter ? singleHostBpf(activeBpfFilter) : null

  const loadStatus = useCallback(async () => {
    try {
      const { data } = await apiClient.get('/api/network/status')
      setStatus(data)
      setError('')
      // Functional update: avoids depending on `iface` (which would recreate
      // this callback — and with it the polling interval — every time the
      // field is set from the status response).
      setIface(prev => prev || data.interface || '')
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  const loadLists = useCallback(async () => {
    try {
      const [p, f, s, q] = await Promise.all([
        apiClient.get('/api/network/packets', { params: { limit: 200 } }),
        apiClient.get('/api/network/frames', { params: { limit: 200 } }),
        apiClient.get('/api/network/streams'),
        apiClient.get('/api/network/quic'),
      ])
      setPackets(p.data || [])
      setFrames(f.data || [])
      setStreams(s.data || [])
      setQuicConns(Array.isArray(q.data) ? q.data : [])
    } catch {
      // lists are best-effort — status is the source of truth
    }
  }, [])

  const loadInterfaces = useCallback(async () => {
    try {
      const { data } = await apiClient.get('/api/network/interfaces')
      setIfaces(Array.isArray(data) ? data : [])
      setIfaceListFailed(false)
    } catch {
      // Older backend without /interfaces — fall back to the free-text input.
      setIfaceListFailed(true)
    }
  }, [])

  useEffect(() => {
    loadStatus()
    loadInterfaces()
    // Load the buffered lists immediately too — after a reload the UI shows
    // the previous capture's packets/frames instead of waiting for the
    // first 2s tick of a running capture.
    loadLists()
    const interval = setInterval(() => {
      if (status?.running) {
        loadStatus()
        loadLists()
      }
    }, 2000)
    return () => clearInterval(interval)
  }, [loadStatus, loadLists, loadInterfaces, status?.running])

  const handleStart = async () => {
    setError('')
    try {
      await apiClient.post('/api/network/capture/start', {
        interface: iface,
        bpf_filter: advancedBpf ? rawBpf : composedBpf,
        pcap_path: pcapPath || null,
      })
      await loadStatus()
      await loadLists()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleStop = async () => {
    if (stopping) return
    setStopping(true)
    setError('')
    try {
      // Longer timeout than the global 30s: stop tears down the sniffer
      // (join up to 5s), rotation/cleanup tasks and the pcap writer, and
      // must not be aborted mid-teardown (which would leave the engine
      // half-stopped). Retry once — the first attempt may have collided
      // with a busy loop that is now free.
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          await apiClient.post('/api/network/capture/stop', undefined, { timeout: 60000 })
          break
        } catch (err: any) {
          if (attempt === 0) {
            await new Promise((r) => setTimeout(r, 500))
            continue
          }
          throw err
        }
      }
      await loadStatus()
      // The interface set may have changed while capturing (VPN up/down,
      // Wi-Fi switch) — refresh the dropdown for the next start.
      await loadInterfaces()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setStopping(false)
    }
  }

  const toggleProto = (p: 'tcp' | 'udp' | 'icmp' | 'arp') =>
    setProtocols((prev) => ({ ...prev, [p]: !prev[p] }))

  const toggleAdvanced = () =>
    setAdvancedBpf((prev) => {
      // Entering advanced mode seeds the raw field with the composed
      // expression so the user edits from a sane starting point.
      if (!prev && !rawBpf) setRawBpf(composedBpf)
      return !prev
    })

  const openDetail = async (seq?: number) => {
    if (seq == null) return
    setDetailError('')
    setDetailLoading(true)
    try {
      const { data } = await apiClient.get(`/api/network/packets/${seq}`)
      setDetail(data)
      setOpenLayers(new Set((data.layers ?? []).map((_: unknown, i: number) => i)))
    } catch (err: any) {
      setDetailError(err.response?.data?.detail || err.message)
      setDetail(null)
    } finally {
      setDetailLoading(false)
    }
  }

  const closeDetail = () => {
    setDetail(null)
    setDetailError('')
  }

  const openStreamDetail = async (s: StreamSummary) => {
    setStreamDetail(s)
    setStreamDetailError('')
    setStreamDetailLoading(true)
    setStreamFrames([])
    try {
      const { data } = await apiClient.get(`/api/network/streams/${encodeURIComponent(s.stream_id)}/frames`)
      setStreamFrames(Array.isArray(data) ? data : [])
    } catch (err: any) {
      setStreamDetailError(err.response?.data?.detail || err.message)
    } finally {
      setStreamDetailLoading(false)
    }
  }

  const closeStreamDetail = () => {
    setStreamDetail(null)
    setStreamFrames([])
    setStreamDetailError('')
  }

  const openQuicDetail = (f: FrameEntry) => {
    const connId = f.data?.conn_id
    // Prefer the live registry entry — it tracks the growing packet count.
    const live = quicConns.find(c => c.conn_id === connId)
    setQuicDetail({
      summary: live ? { ...f.data, packet_count: live.packet_count, packet_types: live.packet_types, last_seen: live.last_seen } : f.data,
      fiveTuple: f.five_tuple,
    })
  }

  const closeQuicDetail = () => setQuicDetail(null)

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-gray-500">
        Loading Network...
      </div>
    )
  }

  const running = status?.running ?? false
  const stats = status?.stats

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <Activity size={16} />
        <span>Network</span>
        <span className="ml-2 text-[10px] text-gray-600 font-normal">
          Passive capture — HTTP/TLS parsing is delegated to mitmproxy (Proxy tab)
        </span>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>}

        {isVirtualIface && (
          <div
            className="flex items-start gap-2 text-xs text-amber-300 bg-amber-500/10 border border-amber-600/30 rounded p-2"
            role="alert"
          >
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>
              Capturing on <span className="font-mono">{captureIface}</span> — a VPN/virtual adapter.{' '}
              Traffic that doesn't route through it (apps bypassing the tunnel, or the physical
              Wi-Fi/Ethernet) will be invisible. Prefer a physical adapter for full visibility.
            </span>
          </div>
        )}

        {singleHostIp && (
          <div
            className="flex items-start gap-2 text-xs text-amber-300 bg-amber-500/10 border border-amber-600/30 rounded p-2"
            role="alert"
          >
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>
              {status?.running ? 'Capturing' : 'The Advanced BPF will capture'}{' '}
              <span className="font-mono">host {singleHostIp}</span> only — all other traffic is
              excluded at capture time and will never appear in the lists.
            </span>
          </div>
        )}

        {/* Status + controls */}
        <div className="bg-gray-900 border border-gray-800 rounded p-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className={`w-4 h-4 rounded-full ${running ? 'bg-green-500 shadow-lg shadow-green-500/50' : 'bg-red-500 shadow-lg shadow-red-500/50'}`} />
            <div>
              <div className="text-sm font-medium">
                {running ? `Capturing on ${status?.interface || '?'}` : 'Capture stopped'}
              </div>
              <div className="text-[11px] text-gray-500 font-mono">
                {status?.bpf_filter || 'no filter'}
                {status?.pcap_path ? ` · pcap: ${status.pcap_path}` : ''}
              </div>
            </div>
            {(status?.interface_changes ?? 0) > 0 && (
              <span
                className="flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-amber-500/10 text-amber-300 border border-amber-600/30"
                title="The capture watchdog re-bound to the active interface this often (e.g. Wi-Fi → VPN → Ethernet switches)"
              >
                <RefreshCw size={10} />
                {status?.interface_changes} interface change{(status?.interface_changes ?? 0) === 1 ? '' : 's'}
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {ifaceListFailed ? (
              // /api/network/interfaces unavailable (older backend) — keep the
              // free-text fallback so capture still works.
              <input
                value={iface}
                onChange={(e) => setIface(e.target.value)}
                disabled={running}
                placeholder="Interface (e.g. Wi-Fi, 'auto' = active)"
                className="bg-gray-950 border border-gray-800 rounded px-2 py-1.5 text-xs text-gray-200 w-56 disabled:opacity-50"
              />
            ) : (
              <select
                value={iface}
                onChange={(e) => setIface(e.target.value)}
                disabled={running}
                className="bg-gray-950 border border-gray-800 rounded px-2 py-1.5 text-xs text-gray-200 w-56 disabled:opacity-50"
              >
                <option value="auto">Auto — follow active interface</option>
                {ifaces.map((i) => (
                  <option key={i.name} value={i.name}>
                    {i.name}
                    {i.is_default ? ' — active' : ''}
                    {!i.is_up ? ' (down)' : ''}
                    {i.is_loopback ? ' (loopback)' : ''}
                  </option>
                ))}
              </select>
            )}
            {/* BPF filter: protocol checkboxes compose the expression; the
                Advanced toggle swaps in a raw BPF input for power users. */}
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-1.5">
                {(['tcp', 'udp', 'icmp', 'arp'] as const).map((p) => (
                  <label
                    key={p}
                    title={`Capture ${p.toUpperCase()} packets`}
                    className={`flex items-center gap-1 px-1.5 py-1 rounded border text-[10px] select-none cursor-pointer disabled:opacity-50 ${
                      protocols[p]
                        ? 'bg-blue-600/20 border-blue-700/40 text-blue-200'
                        : 'bg-gray-950 border-gray-800 text-gray-500'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={protocols[p]}
                      disabled={running}
                      onChange={() => toggleProto(p)}
                      aria-label={p.toUpperCase()}
                      className="accent-blue-500"
                    />
                    {p.toUpperCase()}
                  </label>
                ))}
                <label className="flex items-center gap-1 px-1.5 py-1 text-[10px] text-gray-400 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={advancedBpf}
                    disabled={running}
                    onChange={toggleAdvanced}
                    aria-label="Advanced BPF"
                    className="accent-purple-500"
                  />
                  Advanced
                </label>
              </div>
              {advancedBpf ? (
                <input
                  value={rawBpf}
                  onChange={(e) => setRawBpf(e.target.value)}
                  disabled={running}
                  placeholder="raw BPF, e.g. tcp port 443 or arp"
                  className="bg-gray-950 border border-gray-800 rounded px-2 py-1.5 text-xs text-gray-200 font-mono w-56 disabled:opacity-50"
                />
              ) : (
                <span className="text-[10px] text-gray-500 font-mono pl-0.5">
                  → {composedBpf || 'no protocol selected'}
                </span>
              )}
            </div>
            <input
              value={pcapPath}
              onChange={(e) => setPcapPath(e.target.value)}
              disabled={running}
              placeholder="Save to .pcap path (optional)"
              className="bg-gray-950 border border-gray-800 rounded px-2 py-1.5 text-xs text-gray-200 w-52 disabled:opacity-50"
            />
            {!running ? (
              <button
                onClick={handleStart}
                disabled={!advancedBpf && !composedBpf}
                title={!advancedBpf && !composedBpf ? 'Select at least one protocol (or use Advanced)' : undefined}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600 hover:bg-green-500 text-white text-xs font-medium rounded transition-colors disabled:bg-gray-700 disabled:text-gray-400 disabled:cursor-not-allowed"
              >
                <Play size={14} />
                Start Capture
              </button>
            ) : (
              <button
                onClick={handleStop}
                disabled={stopping}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white text-xs font-medium rounded transition-colors disabled:bg-red-800 disabled:text-red-300 disabled:cursor-wait"
              >
                <StopCircle size={14} />
                {stopping ? 'Stopping…' : 'Stop'}
              </button>
            )}
            <a
              href="/api/network/export"
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                running && (status?.packets_buffered ?? 0) > 0
                  ? 'bg-gray-800 hover:bg-gray-700 text-gray-200'
                  : 'bg-gray-800/40 text-gray-600 pointer-events-none'
              }`}
            >
              <Download size={14} />
              Export .pcap
            </a>
          </div>
        </div>

        {/* Live stats */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
            <StatCard icon={<Radio size={12} />} label="PPS" value={(stats.pps ?? 0).toFixed(1)} accent="text-purple-300" />
            <StatCard icon={<Waves size={12} />} label="BPS" value={formatBytes(stats.bps ?? 0) + '/s'} accent="text-purple-300" />
            <StatCard icon={<Activity size={12} />} label="Packets" value={String(stats.packets_total)} />
            <StatCard icon={<Waves size={12} />} label="Bytes" value={formatBytes(stats.bytes_total)} />
            <StatCard icon={<GitBranch size={12} />} label="TCP streams" value={String(stats.tcp_streams)} accent="text-blue-300" />
            {status?.quic_connections != null && status.quic_connections > 0 && (
              <StatCard icon={<Waves size={12} />} label="QUIC conns" value={String(status.quic_connections)} accent="text-orange-300" />
            )}
            <StatCard icon={<Globe size={12} />} label="UDP flows" value={String(stats.udp_flows)} accent="text-blue-300" />
            <StatCard icon={<Activity size={12} />} label="Frames" value={String(status?.frames_buffered ?? 0)} />
            <StatCard icon={<Activity size={12} />} label="Errors" value={String(stats.errors)} accent="text-red-300" />
          </div>
        )}

        {/* Protocol breakdown */}
        {stats && Object.keys(stats.by_protocol).length > 0 && (
          <div className="flex flex-wrap gap-2">
            {Object.entries(stats.by_protocol).map(([proto, count]) => (
              <span key={proto} className="px-2 py-1 text-[11px] rounded bg-gray-900 border border-gray-800 text-gray-300 font-mono">
                {proto}: {count}
              </span>
            ))}
          </div>
        )}

        {/* Packet list */}
        <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
          <div className="px-3 py-2 border-b border-gray-800 text-xs font-medium text-gray-400 flex items-center justify-between">
            <span className="flex items-center gap-1.5"><Radio size={12} /> Packets ({packets.length})</span>
            {packets.length > 0 && <span className="text-[10px] text-gray-600">double-click a packet for details</span>}
            {!running && packets.length === 0 && <span className="text-[10px] text-gray-600">start a capture to see packets</span>}
          </div>
          <div className="max-h-56 overflow-y-auto">
            {packets.length === 0 ? (
              <div className="p-4 text-xs text-gray-500 text-center">No packets captured yet.</div>
            ) : (
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-gray-900 text-gray-500">
                  <tr className="text-left border-b border-gray-800">
                    <th className="px-3 py-1.5 font-medium">Time</th>
                    <th className="px-3 py-1.5 font-medium">Proto</th>
                    <th className="px-3 py-1.5 font-medium">Source</th>
                    <th className="px-3 py-1.5 font-medium">Destination</th>
                    <th className="px-3 py-1.5 font-medium">Ports</th>
                    <th className="px-3 py-1.5 font-medium text-right">Len</th>
                  </tr>
                </thead>
                <tbody>
                  {packets.slice().reverse().map((p, i) => (
                    <tr
                      key={i}
                      className="border-b border-gray-800/50 last:border-0 hover:bg-gray-800/30 cursor-pointer"
                      onDoubleClick={() => openDetail(p.seq)}
                      title={p.seq != null ? 'Double-click for Wireshark-style details' : undefined}
                    >
                      <td className="px-3 py-1 font-mono text-gray-500">{p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : '—'}</td>
                      <td className="px-3 py-1">
                        <span className={`font-mono ${protoColor(p.proto)}`}>{p.proto}</span>
                      </td>
                      <td className="px-3 py-1 font-mono text-gray-300">{p.src || '—'}</td>
                      <td className="px-3 py-1 font-mono text-gray-300">{p.dst || '—'}</td>
                      <td className="px-3 py-1 font-mono text-gray-500">
                        {p.sport != null ? `${p.sport} → ${p.dport ?? ''}` : p.icmp_type != null ? `type ${p.icmp_type}` : '—'}
                      </td>
                      <td className="px-3 py-1 text-right font-mono text-gray-400">{p.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Decoded frames */}
        <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
          <div className="px-3 py-2 border-b border-gray-800 text-xs font-medium text-gray-400">
            Decoded frames ({frames.length})
          </div>
          <div className="max-h-56 overflow-y-auto">
            {frames.length === 0 ? (
              <div className="p-4 text-xs text-gray-500 text-center">No protocol frames yet (DNS/DHCP/ARP/ICMP/QUIC).</div>
            ) : (
              <table className="w-full text-xs">
                <tbody>
                  {frames.slice().reverse().map((f, i) => (
                    <tr
                      key={i}
                      className={`border-b border-gray-800/50 last:border-0 hover:bg-gray-800/30 ${f.frame_type === 'quic' ? 'cursor-pointer' : ''}`}
                      onDoubleClick={() => f.frame_type === 'quic' && openQuicDetail(f)}
                      title={f.frame_type === 'quic' ? 'Double-click for connection details' : undefined}
                    >
                      <td className="px-3 py-1 font-mono text-gray-500 w-20 shrink-0">{f.timestamp ? new Date(f.timestamp).toLocaleTimeString() : '—'}</td>
                      <td className="px-3 py-1 w-24 shrink-0">
                        <span className={`font-mono ${frameColor(f.frame_type)}`}>{f.frame_type}</span>
                      </td>
                      <td className="px-3 py-1 text-gray-300 truncate">{frameSummary(f)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* QUIC connections (aggregated per DCID) — shown once any exist,
            collapsible since it only matters on QUIC-heavy browsing. */}
        {quicConns.length > 0 && (
          <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
            <button
              type="button"
              className="w-full px-3 py-2 border-b border-gray-800 text-xs font-medium text-gray-400 flex items-center justify-between hover:bg-gray-800/40"
              onClick={() => setShowQuic(v => !v)}
            >
              <span className="flex items-center gap-1.5">
                {showQuic ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                QUIC connections ({quicConns.length})
              </span>
              <span className="text-[10px] text-gray-600">HTTP/3, aggregated per connection ID — click to {showQuic ? 'hide' : 'expand'}</span>
            </button>
            {showQuic && (
              <div className="max-h-56 overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-gray-900 text-gray-500">
                    <tr className="text-left border-b border-gray-800">
                      <th className="px-3 py-1.5 font-medium">Last seen</th>
                      <th className="px-3 py-1.5 font-medium">Peer</th>
                      <th className="px-3 py-1.5 font-medium">Ver</th>
                      <th className="px-3 py-1.5 font-medium">Conn ID</th>
                      <th className="px-3 py-1.5 font-medium">Packets</th>
                      <th className="px-3 py-1.5 font-medium">Breakdown</th>
                    </tr>
                  </thead>
                  <tbody>
                    {quicConns.map((c) => (
                      <tr key={c.conn_id} className="border-b border-gray-800/50 last:border-0 hover:bg-gray-800/30">
                        <td className="px-3 py-1 font-mono text-gray-500">{c.last_seen ? new Date(c.last_seen).toLocaleTimeString() : '—'}</td>
                        <td className="px-3 py-1 font-mono text-gray-300">{quicPeer(c.five_tuple)}</td>
                        <td className="px-3 py-1 font-mono text-orange-300">{quicVersion(c.version)}</td>
                        <td className="px-3 py-1 font-mono text-gray-500" title={c.dcid || c.conn_id}>{(c.dcid || c.conn_id).slice(0, 12)}…</td>
                        <td className="px-3 py-1 font-mono text-gray-300">{c.packet_count}</td>
                        <td className="px-3 py-1 font-mono text-gray-500">
                          {Object.entries(c.packet_types || {}).map(([t, n]) => `${t}×${n}`).join(' + ') || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Streams */}
        <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
          <div className="px-3 py-2 border-b border-gray-800 text-xs font-medium text-gray-400">
            Streams ({streams.length})
          </div>
          <div className="max-h-72 overflow-y-auto">
            {streams.length === 0 ? (
              <div className="p-4 text-xs text-gray-500 text-center">No streams yet.</div>
            ) : (
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-gray-900 text-gray-500">
                  <tr className="text-left border-b border-gray-800">
                    <th className="px-3 py-1.5 font-medium">Type</th>
                    <th className="px-3 py-1.5 font-medium">Five-tuple</th>
                    <th className="px-3 py-1.5 font-medium">SNI</th>
                    <th className="px-3 py-1.5 font-medium">Frames</th>
                    <th className="px-3 py-1.5 font-medium text-right">Bytes</th>
                    <th className="px-3 py-1.5 font-medium">Link</th>
                  </tr>
                </thead>
                <tbody>
                  {streams.map((s) => (
                    <tr
                      key={s.stream_id}
                      className="border-b border-gray-800/50 last:border-0 hover:bg-gray-800/30 cursor-pointer"
                      onDoubleClick={() => openStreamDetail(s)}
                      title="Double-click for the frame-by-frame conversation"
                    >
                      <td className="px-3 py-1">
                        <span className={`font-mono ${s.transport === 'tcp' ? 'text-blue-300' : 'text-emerald-300'}`}>{s.transport}</span>
                      </td>
                      <td className="px-3 py-1 font-mono text-gray-300">
                        {s.five_tuple.src_ip}:{s.five_tuple.src_port} → {s.five_tuple.dst_ip}:{s.five_tuple.dst_port}
                      </td>
                      <td className="px-3 py-1 font-mono text-gray-400">{s.sni || '—'}</td>
                      <td className="px-3 py-1 text-gray-400">{s.frame_count}</td>
                      <td className="px-3 py-1 text-right font-mono text-gray-400">{s.bytes_total}</td>
                      <td className="px-3 py-1">
                        {s.link ? (
                          <button
                            onClick={(e) => { e.stopPropagation(); navigate('/proxy') }}
                            className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-purple-600/20 text-purple-300 border border-purple-700/30 hover:bg-purple-600/40 transition-colors"
                            title="This flow is intercepted by mitmproxy — open the Proxy tab"
                          >
                            {s.link.protocol} → Proxy tab
                            <ArrowRightCircle size={10} />
                          </button>
                        ) : (
                          <span className="text-[10px] text-gray-600">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* Packet detail modal (double-click a packet row) — Wireshark-style
          layer tree + hexdump bytes pane, served by GET /packets/{seq}. */}
      {(detail || detailError || detailLoading) && (
        <div
          className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
          onClick={closeDetail}
        >
          <div
            className="bg-gray-950 border border-gray-700 rounded-lg shadow-2xl max-w-3xl w-full max-h-[85vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-800">
              <div className="flex items-center gap-2 text-sm text-gray-200 font-medium">
                <ListTree size={14} />
                Packet #{detail?.seq ?? '—'}
                {detail && (
                  <span className="text-[11px] text-gray-500 font-normal font-mono">
                    {detail.proto} · {detail.length} B · {detail.sniffed_on} · {new Date(detail.timestamp).toLocaleTimeString()}
                  </span>
                )}
              </div>
              <button
                onClick={closeDetail}
                aria-label="Close packet detail"
                className="text-gray-500 hover:text-gray-200 transition-colors"
              >
                <X size={16} />
              </button>
            </div>

            <div className="flex-1 overflow-auto p-4 space-y-3">
              {detailError && (
                <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{detailError}</div>
              )}
              {detailLoading && (
                <div className="text-xs text-gray-500">Dissecting packet…</div>
              )}
              {detail && (
                <>
                  <div className="border border-gray-800 rounded overflow-hidden">
                    <div className="px-3 py-1.5 border-b border-gray-800 text-[10px] uppercase tracking-wide text-gray-500">
                      Layers
                    </div>
                    <div>
                      {detail.layers.map((layer, li) => {
                        const open = openLayers.has(li)
                        return (
                          <div key={li} className="border-b border-gray-800/50 last:border-0">
                            <button
                              onClick={() =>
                                setOpenLayers((prev) => {
                                  const next = new Set(prev)
                                  if (next.has(li)) next.delete(li)
                                  else next.add(li)
                                  return next
                                })
                              }
                              className="w-full flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-200 hover:bg-gray-900 text-left"
                            >
                              {open ? <ChevronDown size={12} className="text-gray-500" /> : <ChevronRight size={12} className="text-gray-500" />}
                              <span className={`font-mono ${protoColor(layer.name.toLowerCase())}`}>
                                {layer.name}
                              </span>
                              <span className="text-[10px] text-gray-600">({Object.keys(layer.fields).length} fields)</span>
                            </button>
                            {open && (
                              <div className="bg-gray-900/50 px-3 py-1">
                                {Object.entries(layer.fields).map(([k, v]) => (
                                  <div key={k} className="flex gap-2 py-0.5 text-[11px] leading-relaxed">
                                    <span className="text-gray-500 font-mono w-40 shrink-0 truncate" title={k}>{k}</span>
                                    <span className="text-gray-300 font-mono break-all">
                                      {typeof v === 'object' && v !== null ? v.repr : v}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>

                  {detail.hexdump && (
                    <div className="border border-gray-800 rounded overflow-hidden">
                      <div className="px-3 py-1.5 border-b border-gray-800 text-[10px] uppercase tracking-wide text-gray-500">
                        Bytes
                      </div>
                      <pre className="px-3 py-2 text-[10px] font-mono text-gray-400 overflow-x-auto whitespace-pre">
                        {detail.hexdump}
                      </pre>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Stream detail modal (double-click a stream row) — the stream's
          frame-by-frame conversation, served by GET /streams/{id}/frames. */}
      {(streamDetail || streamDetailError || streamDetailLoading) && (
        <div
          className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
          onClick={closeStreamDetail}
        >
          <div
            className="bg-gray-950 border border-gray-700 rounded-lg shadow-2xl max-w-3xl w-full max-h-[85vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-800">
              <div className="flex items-center gap-2 text-sm text-gray-200 font-medium">
                <GitBranch size={14} />
                {streamDetail ? (
                  <span className="font-mono text-[11px] text-gray-400">
                    {streamDetail.transport.toUpperCase()} · {streamDetail.five_tuple.src_ip}:{streamDetail.five_tuple.src_port} → {streamDetail.five_tuple.dst_ip}:{streamDetail.five_tuple.dst_port}
                    {streamDetail.sni ? ` · ${streamDetail.sni}` : ''}
                  </span>
                ) : (
                  <span>Stream</span>
                )}
              </div>
              <button
                onClick={closeStreamDetail}
                aria-label="Close stream detail"
                className="text-gray-500 hover:text-gray-200 transition-colors"
              >
                <X size={16} />
              </button>
            </div>

            <div className="flex-1 overflow-auto p-4 space-y-1">
              {streamDetailError && (
                <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{streamDetailError}</div>
              )}
              {streamDetailLoading && (
                <div className="text-xs text-gray-500">Loading frames…</div>
              )}
              {!streamDetailLoading && !streamDetailError && streamFrames.length === 0 && (
                <div className="text-xs text-gray-500">No frames captured for this stream.</div>
              )}
              {streamFrames.map((fr, i) => (
                <div
                  key={i}
                  className="flex items-start gap-2 py-1 border-b border-gray-800/40 last:border-0 text-[11px]"
                >
                  <span className="text-gray-600 font-mono shrink-0">
                    {new Date(fr.timestamp).toLocaleTimeString()}
                  </span>
                  <span className={`font-mono shrink-0 ${frameColor(fr.frame_type)}`}>
                    {fr.frame_type}
                  </span>
                  <span className="text-gray-300 font-mono break-all">
                    {frameSummary(fr as FrameEntry)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* QUIC connection detail modal (double-click a 'quic' frames row) —
          the aggregated connection summary; payloads are encrypted, so this
          is metadata only. Live-updates counts from quicConns while open. */}
      {quicDetail && (
        <div
          className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
          onClick={closeQuicDetail}
        >
          <div
            className="bg-gray-950 border border-gray-700 rounded-lg shadow-2xl max-w-lg w-full max-h-[85vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-800">
              <div className="flex items-center gap-2 text-sm text-gray-200 font-medium">
                <Waves size={14} className="text-orange-300" />
                <span className="font-mono text-[11px] text-gray-400">
                  QUIC connection · {String(quicDetail.summary?.dcid || quicDetail.summary?.conn_id || '?').slice(0, 16)}…
                </span>
              </div>
              <button
                onClick={closeQuicDetail}
                aria-label="Close QUIC detail"
                className="text-gray-500 hover:text-gray-200 transition-colors"
              >
                <X size={16} />
              </button>
            </div>

            <div className="flex-1 overflow-auto p-4 space-y-2 text-[11px]">
              <div className="grid grid-cols-2 gap-2">
                <div className="bg-gray-900 rounded p-2">
                  <div className="text-gray-500">Peer</div>
                  <div className="font-mono text-gray-200">{quicPeer(quicDetail.fiveTuple)}</div>
                </div>
                <div className="bg-gray-900 rounded p-2">
                  <div className="text-gray-500">QUIC version</div>
                  <div className="font-mono text-orange-300">{quicVersion(quicDetail.summary?.version ?? null)}</div>
                </div>
                <div className="bg-gray-900 rounded p-2">
                  <div className="text-gray-500">Datagrams captured</div>
                  <div className="font-mono text-gray-200">{quicDetail.summary?.packet_count ?? 0}</div>
                </div>
                <div className="bg-gray-900 rounded p-2">
                  <div className="text-gray-500">Last activity</div>
                  <div className="font-mono text-gray-200">
                    {(() => {
                      const ts = quicDetail.summary?.last_seen || quicDetail.summary?.timestamp
                      return ts ? new Date(ts).toLocaleTimeString() : '—'
                    })()}
                  </div>
                </div>
              </div>

              <div className="bg-gray-900 rounded p-2">
                <div className="text-gray-500 mb-1">Packet types</div>
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(quicDetail.summary?.packet_types || {}).length === 0 ? (
                    <span className="text-gray-500">—</span>
                  ) : (
                    Object.entries(quicDetail.summary?.packet_types || {}).map(([t, n]) => (
                      <span key={t} className="px-2 py-0.5 rounded bg-gray-800 border border-gray-700 font-mono text-gray-300">
                        {t}: {n as number}
                      </span>
                    ))
                  )}
                </div>
              </div>

              <div className="bg-gray-900 rounded p-2">
                <div className="text-gray-500 mb-1">Full connection ID</div>
                <div className="font-mono text-gray-400 break-all">{String(quicDetail.summary?.dcid || quicDetail.summary?.conn_id || '—')}</div>
              </div>

              {quicDetail.fiveTuple && (
                <div className="bg-gray-900 rounded p-2">
                  <div className="text-gray-500 mb-1">Five-tuple</div>
                  <div className="font-mono text-gray-400">
                    {quicDetail.fiveTuple.src_ip}:{quicDetail.fiveTuple.src_port} → {quicDetail.fiveTuple.dst_ip}:{quicDetail.fiveTuple.dst_port} · {quicDetail.fiveTuple.protocol === 17 ? 'UDP' : quicDetail.fiveTuple.protocol}
                  </div>
                </div>
              )}

              <div className="text-gray-600 leading-relaxed">
                QUIC payloads are encrypted — this modal shows connection metadata only
                (datagram volume, types, endpoints). Handshake types (initial/handshake)
                reveal a new connection; a stream of short packets indicates ongoing
                encrypted transfer.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function StatCard({ icon, label, value, accent = 'text-gray-100' }: {
  icon: ReactNode
  label: string
  value: string
  accent?: string
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded p-3">
      <div className="flex items-center gap-1.5 text-xs text-gray-400 mb-1">
        {icon}
        <span>{label}</span>
      </div>
      <div className={`text-lg font-semibold ${accent}`}>{value}</div>
    </div>
  )
}

function protoColor(proto: string): string {
  switch (proto) {
    case 'tcp': return 'text-blue-300'
    case 'udp': return 'text-emerald-300'
    case 'icmp': return 'text-amber-300'
    case 'arp': return 'text-pink-300'
    default: return 'text-gray-400'
  }
}

function frameColor(frameType: string): string {
  switch (frameType) {
    case 'dns': return 'text-emerald-300'
    case 'dhcp': return 'text-cyan-300'
    case 'arp': return 'text-pink-300'
    case 'icmp': return 'text-amber-300'
    case 'quic': return 'text-orange-300'
    case 'tls': return 'text-purple-300'
    default: return 'text-gray-400'
  }
}

function formatBytes(n: number): string {
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB'
  if (n >= 1024) return (n / 1024).toFixed(1) + ' KB'
  return String(Math.round(n)) + ' B'
}

import { useState, useEffect, useCallback, type ReactNode } from 'react'
import { Activity, Play, StopCircle, Download, Radio, Waves, Globe, GitBranch } from 'lucide-react'
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
}

interface PacketSummary {
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

interface FrameEntry {
  frame_type: string
  timestamp: string
  data: Record<string, any>
  five_tuple: any
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
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [iface, setIface] = useState('')
  const [bpf, setBpf] = useState('tcp or udp')
  const [pcapPath, setPcapPath] = useState('')

  const loadStatus = useCallback(async () => {
    try {
      const { data } = await apiClient.get('/api/network/status')
      setStatus(data)
      setError('')
      if (data.interface && !iface) setIface(data.interface)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }, [iface])

  const loadLists = useCallback(async () => {
    try {
      const [p, f, s] = await Promise.all([
        apiClient.get('/api/network/packets', { params: { limit: 200 } }),
        apiClient.get('/api/network/frames', { params: { limit: 200 } }),
        apiClient.get('/api/network/streams'),
      ])
      setPackets(p.data || [])
      setFrames(f.data || [])
      setStreams(s.data || [])
    } catch {
      // lists are best-effort — status is the source of truth
    }
  }, [])

  useEffect(() => {
    loadStatus()
    const interval = setInterval(() => {
      if (status?.running) {
        loadStatus()
        loadLists()
      }
    }, 2000)
    return () => clearInterval(interval)
  }, [loadStatus, loadLists, status?.running])

  const handleStart = async () => {
    setError('')
    try {
      await apiClient.post('/api/network/capture/start', {
        interface: iface,
        bpf_filter: bpf,
        pcap_path: pcapPath || null,
      })
      await loadStatus()
      await loadLists()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleStop = async () => {
    setError('')
    try {
      await apiClient.post('/api/network/capture/stop')
      await loadStatus()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

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
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <input
              value={iface}
              onChange={(e) => setIface(e.target.value)}
              disabled={running}
              placeholder="Interface (e.g. eth0, Wi-Fi, leave empty = all)"
              className="bg-gray-950 border border-gray-800 rounded px-2 py-1.5 text-xs text-gray-200 w-56 disabled:opacity-50"
            />
            <input
              value={bpf}
              onChange={(e) => setBpf(e.target.value)}
              disabled={running}
              placeholder="BPF filter"
              className="bg-gray-950 border border-gray-800 rounded px-2 py-1.5 text-xs text-gray-200 w-40 disabled:opacity-50"
            />
            {!running ? (
              <button
                onClick={handleStart}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600 hover:bg-green-500 text-white text-xs font-medium rounded transition-colors"
              >
                <Play size={14} />
                Start Capture
              </button>
            ) : (
              <button
                onClick={handleStop}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white text-xs font-medium rounded transition-colors"
              >
                <StopCircle size={14} />
                Stop
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
            <StatCard icon={<Radio size={12} />} label="PPS" value={stats.pps.toFixed(1)} accent="text-purple-300" />
            <StatCard icon={<Waves size={12} />} label="BPS" value={formatBytes(stats.bps) + '/s'} accent="text-purple-300" />
            <StatCard icon={<Activity size={12} />} label="Packets" value={String(stats.packets_total)} />
            <StatCard icon={<Waves size={12} />} label="Bytes" value={formatBytes(stats.bytes_total)} />
            <StatCard icon={<GitBranch size={12} />} label="TCP streams" value={String(stats.tcp_streams)} accent="text-blue-300" />
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
                    <tr key={i} className="border-b border-gray-800/50 last:border-0 hover:bg-gray-800/30">
                      <td className="px-3 py-1 font-mono text-gray-500">{new Date(p.timestamp).toLocaleTimeString()}</td>
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
                    <tr key={i} className="border-b border-gray-800/50 last:border-0 hover:bg-gray-800/30">
                      <td className="px-3 py-1 font-mono text-gray-500 w-20 shrink-0">{new Date(f.timestamp).toLocaleTimeString()}</td>
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
                    <tr key={s.stream_id} className="border-b border-gray-800/50 last:border-0 hover:bg-gray-800/30">
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
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-600/20 text-purple-300 border border-purple-700/30">
                            {s.link.protocol} → Proxy tab
                          </span>
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

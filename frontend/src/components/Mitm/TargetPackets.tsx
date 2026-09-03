/**
 * Live packet view for the MITM page.
 *
 * Shows the target-scoped packet feed: a passive capture auto-started with
 * the interception session, BPF-restricted to the selected targets' IPs
 * (plus DHCP 67/68 handshake frames). Same dissection data as the Network
 * tab's packet list — the difference is the lifecycle (MITM-managed) and
 * the scope (targets only, never the whole LAN).
 *
 * Double-click a row for the Wireshark-style detail modal (layer tree +
 * hexdump), served by GET /api/mitm/packets/{seq} — same payload shape as
 * the Network tab's detail endpoint.
 */
import { useEffect, useState } from 'react'
import { ChevronDown, ChevronRight, X } from 'lucide-react'
import {
  getMitmPackets,
  getMitmPacketDetail,
  type MitmPacket,
  type MitmPacketDetail,
  type PacketFeedStatus,
} from '../../api/endpoints/mitm'

function ago(iso: string): string {
  const secs = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (secs < 60) return `${secs}s`
  if (secs < 3600) return `${Math.floor(secs / 60)}m`
  return `${Math.floor(secs / 3600)}h`
}

const PROTO_STYLES: Record<string, string> = {
  tcp: 'bg-sky-600/10 border-sky-700/30 text-sky-300',
  udp: 'bg-emerald-600/10 border-emerald-700/30 text-emerald-300',
  icmp: 'bg-amber-600/10 border-amber-700/30 text-amber-300',
  arp: 'bg-purple-600/10 border-purple-700/30 text-purple-300',
  ip: 'bg-gray-700/40 border-gray-600 text-gray-300',
  other: 'bg-gray-800/70 border-gray-700 text-gray-400',
}

function protoStyle(p: string): string {
  return PROTO_STYLES[p] ?? PROTO_STYLES.other
}

function protoColor(proto: string): string {
  switch (proto.toLowerCase()) {
    case 'tcp': return 'text-blue-300'
    case 'udp': return 'text-emerald-300'
    case 'icmp': return 'text-amber-300'
    case 'arp': return 'text-pink-300'
    default: return 'text-gray-400'
  }
}

/** True when the packet involves one of the selected targets. */
function involves(pkt: MitmPacket, targets: Set<string>): boolean {
  return (
    (!!pkt.src && targets.has(pkt.src)) ||
    (!!pkt.dst && targets.has(pkt.dst)) ||
    // ARP/DHCP handshake frames carry the target at the L3/L2 fields —
    // for ARP specifically the summary maps psrc/pdst onto src/dst.
    (!!pkt.eth_src && targets.has(pkt.eth_src)) ||
    (!!pkt.eth_dst && targets.has(pkt.eth_dst))
  )
}

export function TargetPackets({ feed }: { feed: PacketFeedStatus | undefined }) {
  const [packets, setPackets] = useState<MitmPacket[]>([])
  const [failed, setFailed] = useState(false)
  // Double-click packet detail (Wireshark-style layer tree + hexdump).
  const [detail, setDetail] = useState<MitmPacketDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState('')
  const [openLayers, setOpenLayers] = useState<Set<number>>(new Set())

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const data = await getMitmPackets(120)
        if (alive) {
          setPackets(data)
          setFailed(false)
        }
      } catch {
        if (alive) setFailed(true)
      }
    }
    tick()
    const id = setInterval(tick, 2000)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [])

  const openDetail = async (seq?: number) => {
    if (seq == null) return
    setDetailError('')
    setDetailLoading(true)
    try {
      const d = await getMitmPacketDetail(seq)
      setDetail(d)
      setOpenLayers(new Set((d.layers ?? []).map((_, i: number) => i)))
    } catch (err: any) {
      setDetailError(err?.response?.data?.detail || err?.message || 'Failed to dissect packet')
      setDetail(null)
    } finally {
      setDetailLoading(false)
    }
  }

  const closeDetail = () => {
    setDetail(null)
    setDetailError('')
  }

  if (!feed) return null

  const targets = new Set(feed.targets)
  // Belt-and-braces filter: the BPF already scopes capture, but DHCP frames
  // legitimately carry non-target endpoints — display marks them as relay.
  const targetPkts = packets.filter((p) => involves(p, targets))
  const relayPkts = packets.filter((p) => !involves(p, targets))

  return (
    <div className="mt-6 p-4 rounded-lg border border-gray-800 bg-gray-900/40">
      <div className="flex items-center justify-between mb-1">
        <h3 className="text-sm font-semibold text-gray-300">Packets (network layer)</h3>
        <span className="text-[10px] text-gray-500">
          {feed.running
            ? `live capture on ${feed.interface} — targets only${feed.packets_buffered ? ` · ${feed.packets_buffered} buffered` : ''}`
            : 'feed not running'}
          {targetPkts.length > 0 && <span className="ml-2 text-gray-600">double-click a packet for details</span>}
        </span>
      </div>

      {feed.error ? (
        <p className="text-xs text-amber-400/90 mt-2">
          Packet feed unavailable: {feed.error}. Interception itself is unaffected —
          install Npcap to enable the packet view.
        </p>
      ) : !feed.running ? (
        <p className="text-xs text-gray-500 mt-2">
          The packet feed starts automatically with the interception session.
        </p>
      ) : targetPkts.length === 0 && relayPkts.length === 0 ? (
        <p className="text-xs text-gray-500 mt-2">
          No packets captured yet. The feed shows raw network packets from the
          selected targets (plus DHCP handshake frames) while interception is active.
        </p>
      ) : (
        <>
          <div className="mt-2 overflow-x-auto">
            <table className="w-full text-[11px] font-mono">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="py-1 pr-2 font-normal">when</th>
                  <th className="py-1 pr-2 font-normal">proto</th>
                  <th className="py-1 pr-2 font-normal">source</th>
                  <th className="py-1 pr-2 font-normal">destination</th>
                  <th className="py-1 pr-2 font-normal text-right">len</th>
                </tr>
              </thead>
              <tbody>
                {[...targetPkts].reverse().slice(0, 40).map((p) => (
                  <tr
                    key={p.seq}
                    onDoubleClick={() => openDetail(p.seq)}
                    title="Double-click for Wireshark-style details"
                    className="text-gray-300 border-b border-gray-800/40 hover:bg-gray-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-0.5 pr-2 text-gray-500">{ago(p.timestamp)}</td>
                    <td className="py-0.5 pr-2">
                      <span className={`px-1.5 rounded border ${protoStyle(p.proto)}`}>{p.proto}</span>
                    </td>
                    <td className="py-0.5 pr-2 truncate max-w-[180px]">
                      {p.src ?? p.eth_src ?? '?'}
                      {p.sport != null && <span className="text-gray-500">:{p.sport}</span>}
                    </td>
                    <td className="py-0.5 pr-2 truncate max-w-[180px]">
                      {p.dst ?? p.eth_dst ?? '?'}
                      {p.dport != null && <span className="text-gray-500">:{p.dport}</span>}
                    </td>
                    <td className="py-0.5 text-right text-gray-500">{p.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {relayPkts.length > 0 && (
            <p className="text-[10px] text-gray-600 mt-1">
              +{relayPkts.length} DHCP/handshake frame{relayPkts.length === 1 ? '' : 's'} not
              addressed to a target (capture relayed them during the takeover)
            </p>
          )}
          {failed && (
            <p className="text-[10px] text-amber-500/80 mt-1">
              last poll failed — retrying
            </p>
          )}
        </>
      )}

      {/* Packet detail modal (double-click a row) — layer tree + hexdump
          bytes pane, served by GET /api/mitm/packets/{seq}. */}
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
                Packet #{detail?.seq ?? '…'}
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
    </div>
  )
}

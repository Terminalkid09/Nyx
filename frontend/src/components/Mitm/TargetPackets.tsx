/**
 * Live packet view for the MITM page.
 *
 * Shows the target-scoped packet feed: a passive capture auto-started with
 * the interception session, BPF-restricted to the selected targets' IPs
 * (plus DHCP 67/68 handshake frames). Same dissection data as the Network
 * tab's packet list — the difference is the lifecycle (MITM-managed) and
 * the scope (targets only, never the whole LAN).
 */
import { useEffect, useState } from 'react'
import { getMitmPackets, type MitmPacket, type PacketFeedStatus } from '../../api/endpoints/mitm'

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
                  <tr key={p.seq} className="text-gray-300 border-b border-gray-800/40">
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
    </div>
  )
}

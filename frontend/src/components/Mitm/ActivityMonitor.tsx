/**
 * Live activity monitor: what each intercepted target is contacting RIGHT
 * NOW, from TLS SNI and plain-HTTP Host headers — no decryption required,
 * works even when the target has NOT installed the Nyx CA.
 */
interface ActivityEntry {
  ip: string
  host: string
  count: number
  last_seen: string
}

function ago(iso: string): string {
  const secs = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (secs < 60) return `${secs}s`
  if (secs < 3600) return `${Math.floor(secs / 60)}m`
  return `${Math.floor(secs / 3600)}h`
}

export function ActivityMonitor({ activity }: { activity: ActivityEntry[] }) {
  const targets = new Map<string, ActivityEntry[]>()
  for (const entry of activity) {
    const list = targets.get(entry.ip) ?? []
    list.push(entry)
    targets.set(entry.ip, list)
  }

  return (
    <div className="mt-6 p-4 rounded-lg border border-gray-800 bg-gray-900/40">
      <div className="flex items-center justify-between mb-1">
        <h3 className="text-sm font-semibold text-gray-300">Activity Monitor</h3>
        <span className="text-[10px] text-gray-500">
          domains contacted by each target (SNI + HTTP) — live
        </span>
      </div>
      {activity.length === 0 ? (
        <p className="text-xs text-gray-500 mt-2">
          No contacts observed yet. Generate traffic on the target device —
          visited domains appear here in real time, certificate or not.
        </p>
      ) : (
        <div className="space-y-3 mt-2">
          {[...targets.entries()].map(([ip, entries]) => (
            <div key={ip}>
              <div className="text-[11px] font-mono text-purple-300/80 mb-1">{ip}</div>
              <div className="flex flex-wrap gap-1.5">
                {entries.slice(0, 24).map((e) => (
                  <span
                    key={`${e.ip}:${e.host}`}
                    title={`${e.count} contact${e.count === 1 ? '' : 's'} · ${ago(e.last_seen)} ago`}
                    className={`px-2 py-0.5 rounded font-mono text-[11px] border ${
                      e.count > 3
                        ? 'bg-purple-600/10 border-purple-700/30 text-purple-200'
                        : 'bg-gray-800/70 border-gray-700 text-gray-300'
                    }`}
                  >
                    {e.host}
                    {e.count > 1 && <span className="text-gray-500 ml-1">×{e.count}</span>}
                  </span>
                ))}
                {entries.length > 24 && (
                  <span className="text-[10px] text-gray-500 px-1 self-center">
                    +{entries.length - 24} more
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

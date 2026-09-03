/**
 * Amber diagnostics panel shown when interception is ACTIVE but no flow has
 * been captured recently. Distinguishes "packets arrive but TLS is rejected"
 * (lists the rejected hosts) from "no traffic observed at all", with a
 * troubleshooting checklist.
 */
interface TlsFailedHost {
  host: string
  error: string
  ts: number
}

interface TrafficDiagnosticsPanelProps {
  interceptingButNoFlows: boolean
  packetsForwarded: number
  tlsFailures: number
  tlsFailedHosts: TlsFailedHost[]
  lastTrafficSeen: string | null | undefined
}

export function TrafficDiagnosticsPanel({
  interceptingButNoFlows,
  packetsForwarded,
  tlsFailures,
  tlsFailedHosts,
  lastTrafficSeen,
}: TrafficDiagnosticsPanelProps) {
  return (
    <div className="mt-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
      {interceptingButNoFlows ? (
        <>
          <p className="text-amber-300 font-medium mb-1">
            ⚠ Traffic IS reaching the proxy ({packetsForwarded} packets
            intercepted), but nothing is being decrypted into flows.
          </p>
          <p className="text-amber-200/80 mb-1">
            The handoff works — the target is rejecting the TLS certificate or
            the connections are not HTTPS. Check:
          </p>
          {tlsFailures > 0 && (
            <div className="mb-2 p-2 rounded bg-amber-500/5 border border-amber-500/20">
              <p className="text-amber-200/80 text-xs mb-1">
                The target rejected{' '}
                <strong>
                  {tlsFailures} TLS handshake{tlsFailures === 1 ? '' : 's'}
                </strong>{' '}
                — it does not trust the Nyx CA. Attempted hosts:
              </p>
              <div className="flex flex-wrap gap-1.5">
                {tlsFailedHosts.slice(0, 8).map((f, i) => (
                  <span
                    key={i}
                    className="px-2 py-0.5 rounded bg-gray-800/80 text-amber-200/90 text-[11px] font-mono"
                    title={f.error}
                  >
                    {f.host}
                  </span>
                ))}
                {tlsFailedHosts.length > 8 && (
                  <span className="text-amber-200/60 text-[11px] px-1">
                    +{tlsFailedHosts.length - 8} more
                  </span>
                )}
              </div>
            </div>
          )}
        </>
      ) : (
        <>
          <p className="text-amber-300 font-medium mb-1">
            ⚠ Transport is up, but no traffic has been observed
            {lastTrafficSeen ? ' for a while' : ' yet'}.
          </p>
          <p className="text-amber-200/80 mb-1">
            "ACTIVE" means the redirect and spoofing tasks are running — it
            does not prove traffic is reaching the proxy. Check:
          </p>
        </>
      )}
      <ul className="text-amber-200/70 list-disc list-inside space-y-0.5">
        <li>
          <strong>Firewall:</strong> is the proxy port open for LAN devices?
          (Nyx tries to add a Windows Firewall rule, but it needs Administrator
          rights.)
        </li>
        <li>
          <strong>CA certificate:</strong> HTTPS traffic is only decryptable
          after installing the Nyx CA on the target.
        </li>
        <li>
          <strong>QUIC/HTTP3:</strong> browsers increasingly use QUIC (UDP)
          which bypasses the proxy — disable QUIC on the target (e.g. Chrome
          flags → quic).
        </li>
        <li>
          <strong>Private DNS / DoH / DoT:</strong> targets using a private DNS
          provider won't send plain DNS to the router, so DNS spoofing misses
          them.
        </li>
        <li>
          <strong>Certificate pinning:</strong> apps that pin certificates will
          reject Nyx's CA and stall the connection.
        </li>
        <li>
          <strong>Target activity:</strong> the device must actually generate
          HTTP/HTTPS traffic — open a site on the target.
        </li>
      </ul>
    </div>
  )
}

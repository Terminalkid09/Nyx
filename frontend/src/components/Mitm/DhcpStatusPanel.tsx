import type { MitmStatus } from '../../api/endpoints/mitm'

/**
 * DHCP spoofing status line shown while interception is running: lease
 * accepted / ARP fallback active / fallback countdown / listening.
 */
export function DhcpStatusPanel({ status }: { status: MitmStatus | null }) {
  if (!status?.dhcp_spoofing) return null

  const leaseRequests = status?.dhcp_lease_requests ?? 0
  const offers = status?.dhcp_offers ?? 0
  const fallbackIn = status?.dhcp_fallback_in

  return (
    <div className="mt-2 space-y-1">
      {leaseRequests > 0 ? (
        <p className="text-green-400">
          ✓ DHCP lease accepted by the target — its traffic flows through Nyx
          as the gateway (no "suspicious activity" alert).
        </p>
      ) : status?.arp_spoofing ? (
        <p className="text-amber-400 mt-2">
          DHCP did not produce a lease — <strong>ARP fallback active</strong>.
          A "suspicious activity" alert may appear on the target. For the DHCP
          path: on the phone{' '}
          <strong>"forget the Wi-Fi network"</strong> and reconnect.
        </p>
      ) : fallbackIn != null ? (
        <p className="text-amber-400 mt-2">
          ⚠{' '}
          {offers > 0
            ? 'OFFER sent but not accepted (the router answered first)'
            : 'No DHCP request from the target yet'}{' '}
          — automatic ARP fallback in ~{Math.max(1, Math.ceil(fallbackIn))}s.
          For the DHCP path: on the phone{' '}
          <strong>"forget the Wi-Fi network"</strong> and reconnect (a simple
          toggle only renews the lease with the router, which Nyx never sees).
        </p>
      ) : (
        <p className="text-green-400/80">DHCP active, listening on UDP/67.</p>
      )}
    </div>
  )
}

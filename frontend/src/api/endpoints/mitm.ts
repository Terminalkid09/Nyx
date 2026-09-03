import { apiClient } from '../client'

export interface MitmStatus {
  active: boolean
  transport_ready?: boolean
  arp_spoofing: boolean
  ndp_spoofing?: boolean
  dhcp_spoofing?: boolean
  dhcp_offers?: number
  dhcp_lease_requests?: number
  dhcp_naks?: number
  dhcp_granted_ips?: string[]
  dhcp_fallback_in?: number | null
  last_arp_sent?: string | null
  forwarded_packets?: number
  forwarded_last_seen?: string | null
  tls_handshake_failures?: number
  tls_failed_hosts?: Array<{ host: string; error: string; ts: number }>
  dns_spoofing: boolean
  dns_spoof_error?: string | null
  target_ips: string[]
  gateway_ip: string | null
  admin_mode: boolean
  proxy_mode?: string | null
  redirect_active?: boolean
  captured_flows?: number
  last_traffic_seen?: string | null
  local_ip?: string | null
  proxy_host?: string | null
  proxy_port?: number | null
  tls_mitm?: boolean
  quic_blocked_packets?: number
  // "drop" (force TCP fallback, default) | "allow" (QUIC passes through)
  quic_mode?: 'drop' | 'allow'
  udp_policy?: UdpPolicy
  activity?: Array<{ ip: string; host: string; count: number; last_seen: string }>
  // Target-scoped packet feed (auto start/stop with the session)
  packet_feed?: PacketFeedStatus
}

export interface PacketFeedStatus {
  running: boolean
  interface: string | null
  targets: string[]
  packets_buffered: number
  error: string | null
  started_ts: number | null
}

/** One packet summary from GET /api/mitm/packets (same shape as the
 *  Network tab's packet list — src/dst/proto/ports, no payload). */
export interface MitmPacket {
  seq: number
  timestamp: string
  length: number
  proto: 'tcp' | 'udp' | 'icmp' | 'arp' | 'ip' | 'other'
  src?: string
  dst?: string
  sport?: number
  dport?: number
  eth_src?: string
  eth_dst?: string
}

export interface UdpRule {
  target: string
  dst_port: number | null
  action: 'drop' | 'pass'
}

export interface UdpPolicy {
  rules: UdpRule[]
  matched?: number
  dropped?: number
}

export interface NetworkDevice {
  ip: string
  mac: string | null
  hostname: string | null
  vendor: string | null
  is_local: boolean
}

export interface MitmStartRequest {
  target_ips: string[]
  gateway_ip: string
  enable_dns_spoof: boolean
  spoof_method?: 'auto' | 'arp' | 'dhcp'
  arp_mode?: 'reactive' | 'active'
  enable_wifi_ap?: boolean
}

export async function getMitmStatus(): Promise<MitmStatus> {
  const { data } = await apiClient.get('/api/mitm/status')
  return data
}

// MITM start/stop tear down and re-bring-up the transparent proxy, run
// reachability probes and restore ARP/NDP caches — that legitimately takes
// tens of seconds on a real LAN. The global client timeout (30s) is far too
// short for these and made Stop look broken (request aborted client-side,
// button flipping back to clickable while the backend was still tearing down).
const MITM_HEAVY_TIMEOUT = 120000

export async function startMitm(req: MitmStartRequest): Promise<{ session_id?: string }> {
  const { data } = await apiClient.post('/api/mitm/start', req, { timeout: MITM_HEAVY_TIMEOUT })
  return data
}

export async function stopMitm(): Promise<{ status: string }> {
  const { data } = await apiClient.post('/api/mitm/stop', undefined, { timeout: MITM_HEAVY_TIMEOUT })
  return data
}

export async function setTlsMitm(active: boolean): Promise<{ tls_mitm: boolean }> {
  const { data } = await apiClient.post('/api/mitm/tls', { active })
  return data
}

export async function setQuicMode(mode: 'drop' | 'allow'): Promise<{ mode: 'drop' | 'allow' }> {
  const { data } = await apiClient.post('/api/mitm/quic', { mode })
  return data
}

export async function getUdpPolicy(): Promise<UdpPolicy> {
  const { data } = await apiClient.get('/api/mitm/udp')
  return data
}

export async function addUdpRule(rule: {
  target: string
  dst_port: number | null
  action: 'drop' | 'pass'
}): Promise<UdpPolicy> {
  const { data } = await apiClient.post('/api/mitm/udp/rules', rule)
  return data
}

export async function removeUdpRule(index: number): Promise<UdpPolicy> {
  const { data } = await apiClient.delete(`/api/mitm/udp/rules/${index}`)
  return data
}

export async function clearUdpPolicy(): Promise<UdpPolicy> {
  const { data } = await apiClient.post('/api/mitm/udp/clear')
  return data
}

export async function scanNetwork(): Promise<NetworkDevice[]> {
  const { data } = await apiClient.get('/api/mitm/scan-network')
  return data
}

export async function getCaCertUrl(): Promise<string> {
  return '/api/ca-certificate'
}

export async function getMitmPackets(limit = 120): Promise<MitmPacket[]> {
  const { data } = await apiClient.get('/api/mitm/packets', { params: { limit } })
  return Array.isArray(data) ? data : []
}

/** Wireshark-style dissection of one feed packet (same shape as the
 *  Network tab's GET /api/network/packets/{seq}). */
export interface MitmPacketDetail {
  seq: number
  timestamp: string
  length: number
  sniffed_on: string
  proto: string
  layers: Array<{ name: string; fields: Record<string, string | { repr: string; raw: number }> }>
  hexdump: string
}

export async function getMitmPacketDetail(seq: number): Promise<MitmPacketDetail> {
  const { data } = await apiClient.get(`/api/mitm/packets/${seq}`)
  return data
}

export async function removeCaFromHost(): Promise<{ status: string; message: string }> {
  const { data } = await apiClient.post('/api/ca/remove')
  return data
}

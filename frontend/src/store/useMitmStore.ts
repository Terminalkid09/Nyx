/**
 * useMitmStore — Zustand store for the MITM module.
 *
 * Persists the values that are expensive to re-obtain (scan results,
 * selected targets, gateway IP, options) so navigating away and back
 * does NOT reset the UI to a blank state.
 *
 * State that is purely transient (loading spinners, error messages) is
 * kept in-memory only (no persist) because it has no meaning after reload.
 */
import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { NetworkDevice } from '../api/endpoints/mitm'

interface MitmState {
  // ── Persisted ──────────────────────────────────────────────
  /** Devices found by the last successful network scan */
  devices: NetworkDevice[]
  /** IPs currently selected as MITM targets */
  selectedIps: Set<string>
  /** Gateway IP (auto-detected or manually set) */
  gatewayIp: string
  /** Whether DNS spoofing is enabled */
  enableDns: boolean
  /** Spoofing method: 'auto' (DHCP preferred) | 'arp' | 'dhcp' */
  spoofMethod: string
  /** ARP poisoning mode: 'reactive' (stealth, answer-only) | 'active' (flood) */
  arpMode: string
  /** Enable rogue WiFi Access Point mode (target connects to us) */
  enableWifiAp: boolean
  /** Whether a scan has been attempted at least once */
  scanAttempted: boolean

  // ── Transient (in-memory only) ─────────────────────────────
  /** True while a network scan is running */
  scanning: boolean
  /** True while start/stop is in progress */
  loading: boolean
  /** Last error message */
  error: string | null
  /** Text in the manual IP input */
  manualIp: string

  // ── Actions ────────────────────────────────────────────────
  setDevices: (devices: NetworkDevice[]) => void
  setSelectedIps: (ips: Set<string>) => void
  toggleDevice: (ip: string) => void
  selectAll: () => void
  deselectAll: () => void
  addManualIp: () => void
  removeIp: (ip: string) => void
  setGatewayIp: (ip: string) => void
  setEnableDns: (v: boolean) => void
  setSpoofMethod: (v: string) => void
  setArpMode: (v: string) => void
  setEnableWifiAp: (v: boolean) => void
  setScanning: (v: boolean) => void
  setScanAttempted: (v: boolean) => void
  setLoading: (v: boolean) => void
  setError: (e: string | null) => void
  setManualIp: (v: string) => void
}

export const useMitmStore = create<MitmState>()(
  persist(
    (set, get) => ({
      // Persisted defaults
      devices: [],
      selectedIps: new Set<string>(),
      gatewayIp: '192.168.1.1',
      // DNS spoofing is OFF by default: with ARP/DHCP transparent interception
      // the target's traffic already flows through the proxy, and resolving
      // domains to Nyx's own IP can blackhole the target.
      enableDns: false,
      // 'auto' prefers DHCP (no "suspicious network" alert) and falls back to ARP.
      spoofMethod: 'auto',
      // Reactive (answer-only) ARP by default: modern Samsung/Android flag the
      // periodic unsolicited flood, so we only answer when the target asks.
      arpMode: 'reactive',
      // WiFi AP mode off by default (needs driver support)
      enableWifiAp: false,
      scanAttempted: false,

      // Transient defaults
      scanning: false,
      loading: false,
      error: null,
      manualIp: '',

      setDevices: (devices) => set({ devices }),

      setSelectedIps: (ips) => set({ selectedIps: ips }),

      toggleDevice: (ip) =>
        set((s) => {
          const next = new Set(s.selectedIps)
          if (next.has(ip)) next.delete(ip)
          else next.add(ip)
          return { selectedIps: next }
        }),

      selectAll: () =>
        set((s) => ({ selectedIps: new Set(s.devices.map((d) => d.ip)) })),

      deselectAll: () => set({ selectedIps: new Set() }),

      addManualIp: () => {
        const ip = get().manualIp.trim()
        if (!ip) return
        const parts = ip.split('.').map(Number)
        if (
          parts.length !== 4 ||
          parts.some((p) => isNaN(p) || p < 0 || p > 255)
        )
          return
        set((s) => {
          const next = new Set(s.selectedIps)
          next.add(ip)
          return { selectedIps: next, manualIp: '' }
        })
      },

      removeIp: (ip) =>
        set((s) => {
          const next = new Set(s.selectedIps)
          next.delete(ip)
          return { selectedIps: next }
        }),

      setGatewayIp: (ip) => set({ gatewayIp: ip }),
      setEnableDns: (v) => set({ enableDns: v }),
      setSpoofMethod: (v) => set({ spoofMethod: v }),
      setArpMode: (v) => set({ arpMode: v }),
      setEnableWifiAp: (v) => set({ enableWifiAp: v }),
      setScanning: (v) => set({ scanning: v }),
      setScanAttempted: (v) => set({ scanAttempted: v }),
      setLoading: (v) => set({ loading: v }),
      setError: (e) => set({ error: e }),
      setManualIp: (v) => set({ manualIp: v }),
    }),
    {
      // v2: DNS spoofing now defaults OFF and spoof_method was added — bumping
      // the key resets stale persisted state so the safe defaults take effect.
      name: 'nyx-mitm-store-v2',
      // Persist only the values that are expensive to re-obtain.
      // Sets are not JSON-serialisable natively, so we serialise selectedIps
      // as an array and restore it.
      partialize: (s) => ({
        devices: s.devices,
        selectedIps: Array.from(s.selectedIps),
        gatewayIp: s.gatewayIp,
        enableDns: s.enableDns,
        spoofMethod: s.spoofMethod,
        arpMode: s.arpMode,
        enableWifiAp: s.enableWifiAp,
        scanAttempted: s.scanAttempted,
      }),
      // Re-hydrate Set from stored array
      merge: (persisted: any, current) => ({
        ...current,
        ...persisted,
        selectedIps: new Set<string>(persisted.selectedIps ?? []),
      }),
    }
  )
)

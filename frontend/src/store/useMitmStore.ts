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
      enableDns: true,
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
      setScanning: (v) => set({ scanning: v }),
      setScanAttempted: (v) => set({ scanAttempted: v }),
      setLoading: (v) => set({ loading: v }),
      setError: (e) => set({ error: e }),
      setManualIp: (v) => set({ manualIp: v }),
    }),
    {
      name: 'nyx-mitm-store',
      // Persist only the values that are expensive to re-obtain.
      // Sets are not JSON-serialisable natively, so we serialise selectedIps
      // as an array and restore it.
      partialize: (s) => ({
        devices: s.devices,
        selectedIps: Array.from(s.selectedIps),
        gatewayIp: s.gatewayIp,
        enableDns: s.enableDns,
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

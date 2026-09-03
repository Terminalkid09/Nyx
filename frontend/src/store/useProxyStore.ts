import { create } from 'zustand'
import { NyxRequest } from '../types'

interface ProxyFilter {
  method?: string
  host?: string
  status?: number
  flagged?: boolean
  search?: string
  api_type?: string
}

interface ProxyState {
  requests: NyxRequest[]
  selectedId: string | null
  filter: ProxyFilter
  addRequest: (req: NyxRequest) => void
  updateResponse: (id: string, data: Partial<NyxRequest>) => void
  select: (id: string | null) => void
  setFilter: (f: Partial<ProxyFilter>) => void
  clearRequests: () => void
}

export const useProxyStore = create<ProxyState>((set) => ({
  requests: [],
  selectedId: null,
  filter: {},
  addRequest: (req) =>
    set((s) => {
      // Newest first, capped at MAX_REQUESTS. At the cap, drop the oldest
      // entry and prepend — one array copy instead of spread+slice. Avoids
      // an O(n) pass on every request event during busy interception.
      const cur = s.requests
      if (cur.length >= 10000) {
        const requests = cur.slice(0, 9999)
        requests.unshift(req)
        return { requests }
      }
      return { requests: [req, ...cur] }
    }),
  updateResponse: (id, data) =>
    set((s) => {
      // Responses arrive for the most recently added requests (which are
      // prepended), so scan from the front — typically found in 1-2
      // iterations. The previous implementation called .map() over all
      // 10k requests on EVERY response event, which made the UI stutter
      // during MITM sessions.
      const arr = s.requests
      for (let i = 0; i < arr.length; i++) {
        if (arr[i].id === id) {
          const requests = arr.slice()
          requests[i] = { ...requests[i], ...data }
          return { requests }
        }
      }
      return s
    }),
  select: (id) => set({ selectedId: id }),
  setFilter: (f) => set((s) => ({ filter: { ...s.filter, ...f } })),
  clearRequests: () => set({ requests: [], selectedId: null }),
}))

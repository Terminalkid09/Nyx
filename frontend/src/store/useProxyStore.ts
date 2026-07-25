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
    set((s) => ({ requests: [req, ...s.requests].slice(0, 10000) })),
  updateResponse: (id, data) =>
    set((s) => ({
      requests: s.requests.map((r) =>
        r.id === id ? { ...r, ...data } : r
      ),
    })),
  select: (id) => set({ selectedId: id }),
  setFilter: (f) => set((s) => ({ filter: { ...s.filter, ...f } })),
  clearRequests: () => set({ requests: [], selectedId: null }),
}))

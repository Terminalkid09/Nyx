import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { NyxSession } from '../types'
import { apiClient } from '../api/client'
import { useProxyStore } from './useProxyStore'
import { useFindingsStore } from './useFindingsStore'

export const DEFAULT_SESSION_ID = '00000000-0000-0000-0000-000000000001'

interface SessionState {
  sessions: NyxSession[]
  activeSessionId: string
  loading: boolean
  setSessions: (sessions: NyxSession[]) => void
  setActiveSession: (id: string) => void
  fetchSessions: () => Promise<void>
  createSession: (name: string) => Promise<NyxSession>
  deleteSession: (id: string) => Promise<void>
  activateSession: (id: string) => Promise<void>
}

export const useSessionStore = create<SessionState>()(
  persist(
    (set, _get) => ({
      sessions: [],
      activeSessionId: DEFAULT_SESSION_ID,
      loading: false,

      setSessions: (sessions) => set({ sessions }),
      setActiveSession: (id: string) => set({ activeSessionId: id }),

      fetchSessions: async () => {
        set({ loading: true })
        try {
          const { data } = await apiClient.get<NyxSession[]>('/api/sessions')
          set({ sessions: data, loading: false })
        } catch {
          set({ loading: false })
        }
      },

      createSession: async (name: string) => {
        const { data } = await apiClient.post<NyxSession>('/api/sessions', { name })
        set((s) => ({ sessions: [data, ...s.sessions] }))
        return data
      },

      deleteSession: async (id: string) => {
        await apiClient.delete(`/api/sessions/${id}`)
        set((s) => ({
          sessions: s.sessions.filter((sess) => sess.id !== id),
          // if we delete the active session, fall back to default
          activeSessionId:
            s.activeSessionId === id ? DEFAULT_SESSION_ID : s.activeSessionId,
        }))
      },

      activateSession: async (id: string) => {
        // 1. Update store + persist
        set({ activeSessionId: id })
        // 2. Tell proxy engine to stamp new traffic with this session_id
        try {
          await apiClient.patch('/api/proxy/session', { session_id: id })
        } catch {
          // non-fatal: proxy may not be running yet
        }
        // 3. Clear live in-memory caches so we don't show stale data
        useProxyStore.getState().clearRequests()
        useFindingsStore.getState().clear()
      },
    }),
    {
      name: 'nyx-session-store',
      partialize: (state) => ({ activeSessionId: state.activeSessionId }),
    }
  )
)

import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { NyxSession } from '../types'
import { apiClient } from '../api/client'

export const DEFAULT_SESSION_ID = '00000000-0000-0000-0000-000000000001'

interface SessionState {
  sessions: NyxSession[]
  activeSessionId: string
  loading: boolean
  setSessions: (sessions: NyxSession[]) => void
  setActiveSession: (id: string) => void
  fetchSessions: () => Promise<void>
  createSession: (name: string) => Promise<NyxSession>
}

export const useSessionStore = create<SessionState>()(
  persist(
    (set, get) => ({
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
        set((s) => ({ sessions: [...s.sessions, data] }))
        return data
      },
    }),
    {
      name: 'nyx-session-store',
      // Persist only the active session choice across reloads
      partialize: (state) => ({ activeSessionId: state.activeSessionId }),
    }
  )
)

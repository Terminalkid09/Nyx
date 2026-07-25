import { create } from 'zustand'
import { NyxFinding } from '../types'

interface FindingsState {
  findings: NyxFinding[]
  addFinding: (f: NyxFinding) => void
  setFindings: (findings: NyxFinding[]) => void
  clear: () => void
}

export const useFindingsStore = create<FindingsState>((set) => ({
  findings: [],
  addFinding: (f) => set((s) => ({ findings: [f, ...s.findings] })),
  setFindings: (findings) => set({ findings }),
  clear: () => set({ findings: [] }),
}))

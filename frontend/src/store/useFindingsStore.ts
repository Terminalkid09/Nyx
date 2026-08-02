import { create } from 'zustand'
import { NyxFinding } from '../types'

const MAX_FINDINGS = 1000

interface FindingsState {
  findings: NyxFinding[]
  addFinding: (f: NyxFinding) => void
  setFindings: (findings: NyxFinding[]) => void
  clear: () => void
}

export const useFindingsStore = create<FindingsState>((set) => ({
  findings: [],
  addFinding: (f) => set((s) => {
    const next = [f, ...s.findings]
    if (next.length > MAX_FINDINGS) next.length = MAX_FINDINGS
    return { findings: next }
  }),
  setFindings: (findings) => set({ findings }),
  clear: () => set({ findings: [] }),
}))

import { create } from 'zustand'

interface FuzzerStore {
  selectedReqId: string
  template: string
  setFuzzerTarget: (reqId: string, template: string) => void
}

export const useFuzzerStore = create<FuzzerStore>((set) => ({
  selectedReqId: '',
  template: '',
  setFuzzerTarget: (reqId, template) => set({ selectedReqId: reqId, template }),
}))

import { create } from 'zustand'

export type JobModule =
  | 'fuzzer'
  | 'content-discovery'
  | 'crawler'
  | 'live-audit'
  | 'auto-scan'
  | 'sequencer'
  | 'scan-jobs'
  | 'pipeline'

export interface JobState {
  id: string
  status?: string
}

interface JobsStore {
  jobs: Partial<Record<JobModule, JobState>>
  setJob: (module: JobModule, id: string, status?: string) => void
  clearJob: (module: JobModule) => void
}

// Shared store so long-running jobs survive module (tab) switching: the
// component unmounts when the route changes, but the job continues on the
// backend. On remount the component reads its active jobId here and resumes
// polling instead of starting from scratch.
export const useJobsStore = create<JobsStore>((set) => ({
  jobs: {},
  setJob: (module, id, status) =>
    set((s) => ({ jobs: { ...s.jobs, [module]: { id, status } } })),
  clearJob: (module) =>
    set((s) => {
      const next = { ...s.jobs }
      delete next[module]
      return { jobs: next }
    }),
}))

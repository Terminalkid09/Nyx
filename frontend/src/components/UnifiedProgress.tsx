import { useState, useEffect, useRef } from 'react'
import { apiClient } from '../api/client'

interface PipelineStatus {
  id: string
  target_url: string
  current_step: string
  progress: number
  status: string
  steps: string[]
  error?: string
}

interface UnifiedProgressProps {
  pipelineId?: string
  steps?: string[]
  currentStep?: string
  progress?: number
  status?: string
  compact?: boolean
}

const STEP_LABELS: Record<string, string> = {
  crawl: 'Crawl',
  discovery: 'Discovery',
  param_extraction: 'Param Extraction',
  fuzz: 'Fuzz',
  active_scan: 'Active Scan',
  report: 'Report',
}

export function UnifiedProgress({
  pipelineId,
  steps: propSteps,
  currentStep: propCurrentStep,
  progress: propProgress,
  status: propStatus,
  compact,
}: UnifiedProgressProps) {
  const [pipeline, setPipeline] = useState<PipelineStatus | null>(null)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const steps = pipeline?.steps || propSteps || []
  const currentStep = pipeline?.current_step || propCurrentStep || ''
  const progress = pipeline?.progress ?? propProgress ?? 0
  const status = pipeline?.status || propStatus || 'running'

  useEffect(() => {
    if (!pipelineId || status !== 'running') return

    const fetchPipeline = () => {
      apiClient.get(`/api/pipeline/${pipelineId}`)
        .then((res) => setPipeline(res.data))
        .catch(() => {})
    }

    fetchPipeline()
    pollingRef.current = setInterval(fetchPipeline, 2000)

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
    }
  }, [pipelineId, status])

  const currentIdx = steps.indexOf(currentStep)

  if (compact) {
    return (
      <div className="flex items-center gap-2">
        <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              status === 'completed' ? 'bg-green-500' :
              status === 'failed' ? 'bg-red-500' :
              status === 'cancelled' ? 'bg-gray-500' :
              'bg-purple-500'
            }`}
            style={{ width: `${progress}%` }}
          />
        </div>
        <span className="text-xs font-mono text-gray-400 w-8 text-right">{progress}%</span>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1">
        {steps.map((step, i) => {
          const isCompleted = currentIdx > i || status === 'completed'
          const isCurrent = step === currentStep && status === 'running'
          const isFailed = step === currentStep && status === 'failed'

          return (
            <div key={step} className="flex-1 flex flex-col items-center gap-1">
              <div
                className={`w-full h-2 rounded-full transition-all duration-500 ${
                  isFailed
                    ? 'bg-red-500'
                    : isCompleted
                      ? 'bg-green-500'
                      : isCurrent
                        ? 'bg-purple-500 animate-pulse shadow-lg shadow-purple-500/50'
                        : 'bg-gray-700'
                }`}
              />
              <span
                className={`text-[10px] font-medium ${
                  isFailed
                    ? 'text-red-400'
                    : isCompleted
                      ? 'text-green-400'
                      : isCurrent
                        ? 'text-purple-400'
                        : 'text-gray-500'
                }`}
              >
                {STEP_LABELS[step] || step}
              </span>
            </div>
          )
        })}
      </div>
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-400">
          {status === 'running' && currentStep
            ? STEP_LABELS[currentStep] || currentStep
            : status === 'completed'
              ? 'Completed'
              : status === 'failed'
                ? 'Failed'
                : status === 'cancelled'
                  ? 'Cancelled'
                  : ''}
        </span>
        <span className="text-xs font-mono text-gray-400">{progress}%</span>
      </div>
    </div>
  )
}

import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldCheck, LayoutDashboard, Wifi, Search, ArrowRight, Settings, CheckCircle, ChevronLeft, ChevronRight } from 'lucide-react'

interface StepProps {
  title: string
  subtitle?: string
  description: string
  icon: React.ReactNode
  bullets?: string[]
}

const STEPS: StepProps[] = [
  {
    title: 'Welcome to Nyx',
    subtitle: 'Your Complete Web Security Testing Suite',
    description: 'Nyx is a Burp Suite alternative with automated scanning, intelligent triage, and one-click pipelines.',
    icon: <ShieldCheck className="w-16 h-16 text-purple-400" />,
  },
  {
    title: 'Smart Dashboard',
    description: 'Your command center. See active scans, recent findings, and quick stats at a glance.',
    icon: <LayoutDashboard className="w-16 h-16 text-purple-400" />,
    bullets: [
      'Active pipelines with progress',
      'Findings grouped by type x endpoint',
      'One-click actions: New Scan, Open Proxy, View Findings',
    ],
  },
  {
    title: 'Proxy & Interceptor',
    description: 'Configure your browser to use 127.0.0.1:8080 as HTTP proxy. All traffic appears here in real-time.',
    icon: <Wifi className="w-16 h-16 text-purple-400" />,
    bullets: [
      'Inspect and modify requests/responses',
      'Auto-scope learning from traffic',
      'Forward, drop, or edit intercepted items',
    ],
  },
  {
    title: 'Automated Scanning',
    description: '106+ security checks across all OWASP categories. Passive checks run automatically on proxy traffic.',
    icon: <Search className="w-16 h-16 text-purple-400" />,
    bullets: [
      'Automatic passive scanning on proxy traffic',
      'Active scanning on target endpoints',
      'Smart triage groups findings by type x endpoint',
    ],
  },
  {
    title: 'One-Click Full Scan',
    description: 'Enter a URL and Nyx does everything: Crawl to Content Discovery to Param Extraction to Fuzz to Active Scan to Report',
    icon: <ArrowRight className="w-16 h-16 text-purple-400" />,
    bullets: [
      'Configurable scan templates (Quick, Full, API)',
      'Real-time progress tracking',
      'Auto-generated reports',
    ],
  },
  {
    title: 'Enterprise Automations',
    description: 'Set it and forget it. Nyx runs on autopilot.',
    icon: <Settings className="w-16 h-16 text-purple-400" />,
    bullets: [
      'Scheduled recurring scans (cron)',
      'Webhook alerts to Slack/Discord',
      'CSRF PoC generation',
    ],
  },
  {
    title: 'Ready to Hack?',
    description: 'Start with a quick scan or open the proxy. Everything you need is in the sidebar.',
    icon: <CheckCircle className="w-16 h-16 text-purple-400" />,
  },
]

export default function OnboardingWizard() {
  const [open, setOpen] = useState(false)
  const [step, setStep] = useState(0)
  const navigate = useNavigate()

  useEffect(() => {
    const done = localStorage.getItem('nyx_onboarding_complete')
    if (!done) setOpen(true)
  }, [])

  const close = useCallback(() => {
    localStorage.setItem('nyx_onboarding_complete', 'true')
    setOpen(false)
  }, [])

  const skip = useCallback(() => {
    localStorage.setItem('nyx_onboarding_complete', 'true')
    setOpen(false)
  }, [])

  const isLast = step === STEPS.length - 1

  if (!open) return null

  const s = STEPS[step]

  return (
    <div className="fixed inset-0 z-[9999] flex items-start justify-center bg-black/50">
      <div className="relative bg-gray-800 border border-gray-700 rounded-xl p-8 max-w-2xl w-full mx-auto mt-20">
        <button
          onClick={skip}
          className="absolute top-3 right-3 text-xs text-gray-500 hover:text-gray-300 transition-colors"
        >
          Skip Tour
        </button>

        <div className="flex flex-col items-center text-center space-y-6">
          <div className="transition-all duration-300">{s.icon}</div>

          <div className="space-y-2">
            <h2 className="text-2xl font-bold text-gray-100">{s.title}</h2>
            {s.subtitle && (
              <p className="text-sm text-purple-400 font-medium">{s.subtitle}</p>
            )}
            <p className="text-sm text-gray-400 max-w-lg">{s.description}</p>
          </div>

          {s.bullets && (
            <ul className="space-y-2 text-left">
              {s.bullets.map((b, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                  <CheckCircle className="w-4 h-4 text-purple-400 mt-0.5 shrink-0" />
                  {b}
                </li>
              ))}
            </ul>
          )}

          {isLast && (
            <div className="flex gap-3 pt-2">
              <button
                onClick={() => navigate('/scan/new')}
                className="bg-purple-600 hover:bg-purple-700 text-white px-5 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
              >
                Start Full Scan
                <ArrowRight className="w-4 h-4" />
              </button>
              <button
                onClick={() => navigate('/proxy')}
                className="bg-gray-700 hover:bg-gray-600 text-gray-200 px-5 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
              >
                Open Proxy
              </button>
            </div>
          )}

          {!isLast && (
            <button
              onClick={() => setStep((p) => Math.min(p + 1, STEPS.length - 1))}
              className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-2 rounded-lg text-sm font-medium transition-colors"
            >
              Get Started
            </button>
          )}
        </div>

        <div className="flex items-center justify-between mt-8 pt-4 border-t border-gray-700">
          <div className="flex items-center gap-1">
            {STEPS.map((_, i) => (
              <div
                key={i}
                className={`w-2 h-2 rounded-full transition-colors ${
                  i === step ? 'bg-purple-500' : 'bg-gray-600'
                }`}
              />
            ))}
          </div>

          <div className="flex items-center gap-2">
            {step > 0 && (
              <button
                onClick={() => setStep((p) => Math.max(p - 1, 0))}
                className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200 transition-colors px-2 py-1"
              >
                <ChevronLeft className="w-3 h-3" />
                Previous
              </button>
            )}
            {step < STEPS.length - 1 && (
              <button
                onClick={() => setStep((p) => Math.min(p + 1, STEPS.length - 1))}
                className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200 transition-colors px-2 py-1"
              >
                Next
                <ChevronRight className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>

        {isLast && (
          <div className="flex items-center justify-center gap-2 mt-4">
            <button
              onClick={close}
              className="text-xs text-purple-400 hover:text-purple-300 transition-colors"
            >
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

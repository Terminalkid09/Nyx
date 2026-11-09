import { useState } from 'react'
import {
  AlertTriangle,
  BadgeCheck,
  CheckCircle2,
  FlaskConical,
  HelpCircle,
  Play,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import { verifyExploit, type VerifyVerdict } from '../../api/endpoints/verifier'
import { useSessionStore } from '../../store/useSessionStore'
import { useToast } from '../Toast'

const VERDICT_STYLE = {
  confirmed: {
    label: 'Confirmed',
    icon: ShieldAlert,
    iconColor: 'text-red-400',
    panel: 'border-red-800/60 bg-red-950/20',
    badge: 'bg-red-400/10 text-red-400',
    description: 'The injected request produced a material change in the response.',
  },
  probable: {
    label: 'Probable',
    icon: AlertTriangle,
    iconColor: 'text-amber-400',
    panel: 'border-amber-800/60 bg-amber-950/20',
    badge: 'bg-amber-400/10 text-amber-400',
    description: 'The response changed, but not enough to rule out page noise.',
  },
  unverified: {
    label: 'Unverified',
    icon: HelpCircle,
    iconColor: 'text-gray-400',
    panel: 'border-gray-800 bg-gray-900/60',
    badge: 'bg-gray-400/10 text-gray-400',
    description: 'The baseline and injected responses are effectively identical.',
  },
} as const

const SIGNAL_LABEL: Record<string, string> = {
  status_changed: 'HTTP status changed',
  body_changed: 'Response body changed',
  time_delta: 'Response time increased by 2s or more',
}

function parseHeaders(raw: string): Record<string, string> {
  const headers: Record<string, string> = {}
  for (const line of raw.split('\n')) {
    const separator = line.indexOf(':')
    if (separator <= 0) continue
    const name = line.slice(0, separator).trim()
    const value = line.slice(separator + 1).trim()
    if (name) headers[name] = value
  }
  return headers
}

function delta(value: number): string {
  return value > 0 ? `+${value}` : String(value)
}

function VerdictResult({ result }: { result: VerifyVerdict }) {
  const style = VERDICT_STYLE[result.verdict]
  const Icon = style.icon

  return (
    <>
      <div className={`rounded-lg border p-3 ${style.panel}`}>
        <div className="flex items-center gap-2">
          <Icon size={18} className={style.iconColor} />
          <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${style.badge}`}>
            {style.label}
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-2">{style.description}</p>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div className="rounded border border-gray-800 bg-gray-950/60 p-2">
          <div className="text-[10px] text-gray-500">Status delta</div>
          <div className="text-sm font-mono text-gray-200">{delta(result.status_delta)}</div>
        </div>
        <div className="rounded border border-gray-800 bg-gray-950/60 p-2">
          <div className="text-[10px] text-gray-500">Body delta</div>
          <div className="text-sm font-mono text-gray-200">{delta(result.length_delta)} B</div>
        </div>
        <div className="rounded border border-gray-800 bg-gray-950/60 p-2">
          <div className="text-[10px] text-gray-500">Time delta</div>
          <div className="text-sm font-mono text-gray-200">{delta(result.time_delta_ms)} ms</div>
        </div>
        <div className="rounded border border-gray-800 bg-gray-950/60 p-2">
          <div className="text-[10px] text-gray-500">Body similarity</div>
          <div className="text-sm font-mono text-gray-200">
            {(result.similarity * 100).toFixed(1)}%
          </div>
        </div>
      </div>

      <div>
        <div className="text-[10px] uppercase tracking-wide text-gray-600 mb-1">Signals</div>
        {result.signals.length === 0 ? (
          <p className="text-xs text-gray-500">No differential signal detected.</p>
        ) : (
          <ul className="space-y-1">
            {result.signals.map((signal) => (
              <li key={signal} className="text-xs text-gray-300 flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                {SIGNAL_LABEL[signal] || signal}
              </li>
            ))}
          </ul>
        )}
      </div>

      <p className="text-[10px] text-gray-600">
        A verdict is evidence, not proof: review the exchange in the Proxy or Repeater before
        adding it to a report.
      </p>
    </>
  )
}

export function Verifier() {
  const { activeSessionId } = useSessionStore()
  const { addToast } = useToast()

  const [url, setUrl] = useState('')
  const [method, setMethod] = useState('GET')
  const [param, setParam] = useState('')
  const [payload, setPayload] = useState('')
  const [headers, setHeaders] = useState('')
  const [body, setBody] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<VerifyVerdict | null>(null)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!url.trim()) {
      addToast('error', 'A target URL is required')
      return
    }
    if (param.trim() && !payload) {
      addToast('error', 'A payload is required when a parameter is set')
      return
    }

    setBusy(true)
    setError('')
    setResult(null)
    try {
      const verdict = await verifyExploit({
        url: url.trim(),
        method,
        headers: parseHeaders(headers),
        body: body || null,
        param: param.trim() || null,
        payload: payload || null,
        session_id: activeSessionId,
      })
      setResult(verdict)
      if (verdict.verdict === 'confirmed') {
        addToast('warning', 'Finding confirmed by differential verification')
      }
    } catch (e: any) {
      const detail = e.response?.data?.detail
      const message = typeof detail === 'string' ? detail : e.message || 'Verification failed'
      setError(message)
      addToast('error', message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-5 overflow-y-auto h-full">
      <div className="flex items-center gap-3">
        <BadgeCheck className="w-6 h-6 text-purple-400" />
        <div>
          <h1 className="text-xl font-bold text-gray-100">Exploit Verifier</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Send a baseline and an injected request, then classify the difference instead of
            trusting a payload signature.
          </p>
        </div>
      </div>

      <div className="flex items-start gap-2 rounded-lg border border-gray-800 bg-gray-900/60 p-3 text-xs text-gray-400">
        <ShieldCheck size={15} className="mt-0.5 shrink-0 text-purple-400" />
        <span>
          Both requests pass the active session scope and every active Rules-of-Engagement profile.
          The injected URL is authorized separately, and a blocked request never leaves the machine.
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <form onSubmit={submit} className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
          <div className="flex items-center gap-2 text-sm font-medium text-gray-300">
            <FlaskConical size={15} /> Hypothesis
          </div>

          <div className="flex gap-2">
            <select
              value={method}
              onChange={(event) => setMethod(event.target.value)}
              className="bg-gray-800 border border-gray-700 rounded px-2 py-2 text-xs text-gray-200"
            >
              {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((verb) => (
                <option key={verb} value={verb}>{verb}</option>
              ))}
            </select>
            <input
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://target.test/api/items?id=1"
              className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs text-gray-200 font-mono placeholder:text-gray-600"
            />
          </div>

          <div className="grid grid-cols-2 gap-2">
            <label className="space-y-1">
              <span className="text-[11px] text-gray-400">Parameter</span>
              <input
                value={param}
                onChange={(event) => setParam(event.target.value)}
                placeholder="id"
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs text-gray-200 font-mono placeholder:text-gray-600"
              />
            </label>
            <label className="space-y-1">
              <span className="text-[11px] text-gray-400">Payload</span>
              <input
                value={payload}
                onChange={(event) => setPayload(event.target.value)}
                placeholder="1' OR 1=1--"
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs text-gray-200 font-mono placeholder:text-gray-600"
              />
            </label>
          </div>
          <p className="text-[10px] text-gray-600">
            Leave parameter empty to compare the URL with itself. The payload is URL-encoded into
            the query string.
          </p>

          <label className="space-y-1 block">
            <span className="text-[11px] text-gray-400">Headers — one per line</span>
            <textarea
              value={headers}
              onChange={(event) => setHeaders(event.target.value)}
              rows={3}
              placeholder={'Authorization: Bearer …\nContent-Type: application/json'}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs text-gray-200 font-mono placeholder:text-gray-600"
            />
          </label>

          <label className="space-y-1 block">
            <span className="text-[11px] text-gray-400">Body</span>
            <textarea
              value={body}
              onChange={(event) => setBody(event.target.value)}
              rows={3}
              placeholder='{"name":"test"}'
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs text-gray-200 font-mono placeholder:text-gray-600"
            />
          </label>

          <button
            type="submit"
            disabled={busy}
            className="w-full flex items-center justify-center gap-2 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 px-4 py-2 rounded text-xs font-medium text-white transition-colors"
          >
            <Play size={13} /> {busy ? 'Verifying…' : 'Verify'}
          </button>
        </form>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3 min-h-[280px]">
          <div className="flex items-center gap-2 text-sm font-medium text-gray-300">
            <CheckCircle2 size={15} /> Verdict
          </div>

          {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-3">{error}</div>}

          {!result && !error && (
            <div className="h-full flex flex-col items-center justify-center text-center py-10">
              <HelpCircle className="w-9 h-9 text-gray-700 mb-2" />
              <p className="text-xs text-gray-500">
                Submit a request to see the differential verdict.
              </p>
              <p className="text-[10px] text-gray-600 mt-1 max-w-xs">
                Confirmed: status change or a clear body difference. Probable: a smaller body
                difference. Unverified: the responses match.
              </p>
            </div>
          )}

          {result && <VerdictResult result={result} />}
        </div>
      </div>
    </div>
  )
}

import { useState } from 'react'
import axios from 'axios'
import { Users, Loader2, Play, AlertTriangle, ShieldQuestion } from 'lucide-react'
import { runAbTest, type AbTestResult } from '../../api/endpoints/abTest'
import { useSessionStore } from '../../store/useSessionStore'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-900',
  high: 'text-orange-400 bg-orange-400/10 border-orange-900',
  medium: 'text-yellow-400 bg-yellow-400/10 border-yellow-900',
  low: 'text-green-400 bg-green-400/10 border-green-900',
  info: 'text-gray-400 bg-gray-400/10 border-gray-700',
}

const VERDICT_STYLES: Record<string, { label: string; className: string }> = {
  suspected_idor: {
    label: 'Suspected IDOR',
    className: 'text-orange-400 bg-orange-400/10 border-orange-900',
  },
  unauthenticated_access: {
    label: 'Unauthenticated access',
    className: 'text-red-400 bg-red-400/10 border-red-900',
  },
  isolated: {
    label: 'Isolated',
    className: 'text-green-400 bg-green-400/10 border-green-900',
  },
}

/** `Name: value` per line → headers object. Blank lines and lines without a
 * colon are ignored: a pasted request block usually carries both. */
function parseHeaders(raw: string): Record<string, string> {
  const headers: Record<string, string> = {}
  for (const line of raw.split(/\r?\n/)) {
    const separator = line.indexOf(':')
    if (separator <= 0) continue
    const name = line.slice(0, separator).trim()
    const value = line.slice(separator + 1).trim()
    if (name) headers[name] = value
  }
  return headers
}

function percent(value: number): string {
  return `${Math.round((Number.isFinite(value) ? value : 0) * 100)}%`
}

const inputClass =
  'w-full bg-gray-950 border border-gray-800 rounded px-2 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-600'

const labelClass = 'block text-[11px] uppercase tracking-wider text-gray-500 mb-1'

export function AbTest() {
  const { activeSessionId } = useSessionStore()

  const [url, setUrl] = useState('')
  const [method, setMethod] = useState('GET')
  const [headers, setHeaders] = useState('')
  const [body, setBody] = useState('')

  const [identityAName, setIdentityAName] = useState('User A')
  const [identityAHeaders, setIdentityAHeaders] = useState('')
  const [identityBName, setIdentityBName] = useState('User B')
  const [identityBHeaders, setIdentityBHeaders] = useState('')
  const [anonymous, setAnonymous] = useState(true)

  const [result, setResult] = useState<AbTestResult | null>(null)
  const [error, setError] = useState('')
  const [running, setRunning] = useState(false)

  const canRun = url.trim().length > 0 && !running

  const run = async () => {
    setRunning(true)
    setError('')
    setResult(null)
    try {
      const response = await runAbTest({
        url: url.trim(),
        method,
        headers: parseHeaders(headers),
        body: body.length > 0 ? body : null,
        identity_a: { name: identityAName.trim() || 'User A', headers: parseHeaders(identityAHeaders) },
        identity_b: { name: identityBName.trim() || 'User B', headers: parseHeaders(identityBHeaders) },
        anonymous,
        session_id: activeSessionId,
      })
      setResult(response)
    } catch (e) {
      // The backend answers 403 for an out-of-scope target and 502 when the
      // replay itself fails: show its explanation verbatim, it is more useful
      // than a generic "request failed".
      if (axios.isAxiosError(e)) {
        const detail = (e.response?.data as { detail?: string } | undefined)?.detail
        setError(detail || e.message)
      } else {
        setError(e instanceof Error ? e.message : String(e))
      }
    } finally {
      setRunning(false)
    }
  }

  const verdict = result ? VERDICT_STYLES[result.verdict] : undefined

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6 overflow-y-auto h-full">
      <div className="flex items-start gap-3">
        <Users className="w-6 h-6 text-purple-400 shrink-0" />
        <div>
          <h1 className="text-xl font-bold text-gray-100">A/B Test</h1>
          <p className="text-xs text-gray-500 mt-1">
            Replays the same request as two identities, plus an anonymous leg: if both
            see each other's data, or nobody has to log in at all, the endpoint has an
            IDOR or a missing authorization check.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3 lg:col-span-2">
          <h2 className="text-sm font-semibold text-gray-200">Request</h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="md:col-span-3">
              <label className={labelClass} htmlFor="ab-url">Target URL</label>
              <input
                id="ab-url"
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://target.test/admin/users/1"
                className={inputClass}
              />
            </div>
            <div>
              <label className={labelClass} htmlFor="ab-method">Method</label>
              <select
                id="ab-method"
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className={inputClass}
              >
                {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className={labelClass} htmlFor="ab-headers">Shared headers (one per line)</label>
            <textarea
              id="ab-headers"
              value={headers}
              onChange={(e) => setHeaders(e.target.value)}
              rows={3}
              spellCheck={false}
              placeholder="Accept: application/json"
              className={`${inputClass} font-mono`}
            />
          </div>
          <div>
            <label className={labelClass} htmlFor="ab-body">Body (optional)</label>
            <textarea
              id="ab-body"
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={3}
              spellCheck={false}
              placeholder='{"userId": 1}'
              className={`${inputClass} font-mono`}
            />
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
          <h2 className="text-sm font-semibold text-gray-200">Identity A</h2>
          <div>
            <label className={labelClass} htmlFor="ab-a-name">Label</label>
            <input
              id="ab-a-name"
              type="text"
              value={identityAName}
              onChange={(e) => setIdentityAName(e.target.value)}
              className={inputClass}
            />
          </div>
          <div>
            <label className={labelClass} htmlFor="ab-a-headers">Headers</label>
            <textarea
              id="ab-a-headers"
              value={identityAHeaders}
              onChange={(e) => setIdentityAHeaders(e.target.value)}
              rows={4}
              spellCheck={false}
              placeholder="Cookie: session=a…"
              className={`${inputClass} font-mono`}
            />
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
          <h2 className="text-sm font-semibold text-gray-200">Identity B</h2>
          <div>
            <label className={labelClass} htmlFor="ab-b-name">Label</label>
            <input
              id="ab-b-name"
              type="text"
              value={identityBName}
              onChange={(e) => setIdentityBName(e.target.value)}
              className={inputClass}
            />
          </div>
          <div>
            <label className={labelClass} htmlFor="ab-b-headers">Headers</label>
            <textarea
              id="ab-b-headers"
              value={identityBHeaders}
              onChange={(e) => setIdentityBHeaders(e.target.value)}
              rows={4}
              spellCheck={false}
              placeholder="Cookie: session=b…"
              className={`${inputClass} font-mono`}
            />
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between gap-3">
        <label className="flex items-center gap-2 text-xs text-gray-400">
          <input
            type="checkbox"
            checked={anonymous}
            onChange={(e) => setAnonymous(e.target.checked)}
            className="accent-purple-600"
          />
          Also send an anonymous request (no credentials)
        </label>
        <button
          onClick={run}
          disabled={!canRun}
          className="flex items-center gap-2 px-4 py-2 rounded bg-purple-600 hover:bg-purple-500 text-xs font-medium text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {running ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
          {running ? 'Replaying…' : 'Run comparison'}
        </button>
      </div>

      {error && (
        <div className="flex items-start gap-2 text-xs text-red-400 bg-red-400/10 border border-red-900/50 rounded p-3">
          <AlertTriangle size={14} className="shrink-0 mt-0.5" />
          <span className="break-words">{error}</span>
        </div>
      )}

      {!result && !error && (
        <div className="flex items-center gap-2 justify-center py-10 text-xs text-gray-600">
          <ShieldQuestion size={16} />
          No comparison yet.
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${
                  verdict?.className || 'text-gray-400 bg-gray-400/10 border-gray-700'
                }`}
              >
                {verdict?.label || result.verdict}
              </span>
              {result.severity && (
                <span
                  className={`px-2 py-0.5 rounded-full text-xs font-medium border ${
                    SEVERITY_COLORS[result.severity] || SEVERITY_COLORS.info
                  }`}
                >
                  {result.severity.toUpperCase()}
                </span>
              )}
              <span className="text-xs text-gray-500">
                confidence {percent(result.confidence)} · similarity {percent(result.similarity)}
              </span>
            </div>

            {result.signals.length > 0 && (
              <ul className="list-disc list-inside space-y-1 text-xs text-gray-300">
                {result.signals.map((signal, index) => (
                  <li key={`${index}-${signal}`}>{signal}</li>
                ))}
              </ul>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {result.samples.map((sample, index) => (
              <div key={`${index}-${sample.label}`} className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-sm font-semibold text-gray-200 truncate">{sample.label}</h3>
                  <span className="text-[11px] text-gray-500 shrink-0">{sample.time_ms} ms</span>
                </div>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-gray-500 font-mono">
                  <span>status {sample.status ?? '—'}</span>
                  <span>{sample.length} bytes</span>
                  {sample.content_type && <span className="truncate">{sample.content_type}</span>}
                  {sample.location && <span className="truncate">→ {sample.location}</span>}
                  {sample.challenge && <span className="text-yellow-500">challenge</span>}
                </div>
                {sample.error && (
                  <div className="text-xs text-red-400 break-words">{sample.error}</div>
                )}
                <pre className="text-[11px] text-gray-300 bg-gray-950 border border-gray-800 rounded p-2 whitespace-pre-wrap break-all max-h-56 overflow-auto">
                  {sample.body_preview || '(empty body)'}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

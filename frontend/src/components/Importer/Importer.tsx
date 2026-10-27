import { useState } from 'react'
import {
  AlertTriangle,
  FileInput,
  Loader2,
  Upload,
  X,
} from 'lucide-react'
import {
  importBurp,
  importOpenApi,
  type OpenApiInventory,
  type OpenApiWarning,
} from '../../api/endpoints/imports'
import { useSessionStore } from '../../store/useSessionStore'

const MAX_RENDERED_ENDPOINTS = 500

const METHOD_COLORS: Record<string, string> = {
  get: 'text-green-400 bg-green-400/10',
  post: 'text-blue-400 bg-blue-400/10',
  put: 'text-amber-400 bg-amber-400/10',
  patch: 'text-purple-400 bg-purple-400/10',
  delete: 'text-red-400 bg-red-400/10',
  head: 'text-gray-400 bg-gray-400/10',
  options: 'text-gray-400 bg-gray-400/10',
}

const WARNING_COLORS: Record<string, string> = {
  high: 'border-red-900/40 bg-red-950/20 text-red-300',
  medium: 'border-yellow-900/40 bg-yellow-950/20 text-yellow-300',
  low: 'border-blue-900/40 bg-blue-950/20 text-blue-300',
  info: 'border-gray-800 bg-gray-900/40 text-gray-400',
}

function methodClass(method: string): string {
  return METHOD_COLORS[method.toLowerCase()] || 'text-gray-300 bg-gray-800'
}

function errorDetail(err: unknown): string {
  const typed = err as { response?: { data?: { detail?: unknown } }; message?: string }
  const detail = typed.response?.data?.detail
  if (typeof detail === 'string' && detail) return detail
  return typed.message || 'Import failed'
}

function WarningRow({ warning }: { warning: OpenApiWarning }) {
  return (
    <div className={`rounded border px-3 py-2 text-xs ${WARNING_COLORS[warning.severity] || WARNING_COLORS.info}`}>
      <div className="flex items-center gap-2">
        <AlertTriangle size={12} className="shrink-0" />
        <span className="font-mono text-[10px] uppercase opacity-80">{warning.code}</span>
        {warning.method && warning.path && (
          <span className="font-mono text-[10px] opacity-70 truncate">
            {warning.method.toUpperCase()} {warning.path}
          </span>
        )}
      </div>
      <p className="mt-1 leading-relaxed">{warning.message}</p>
    </div>
  )
}

type ImportFormat = 'openapi' | 'burp'

export function Importer() {
  const { activeSessionId } = useSessionStore()
  const [format, setFormat] = useState<ImportFormat>('openapi')
  const [document, setDocument] = useState('')
  const [filename, setFilename] = useState<string | undefined>(undefined)
  const [applyScope, setApplyScope] = useState(false)
  const [result, setResult] = useState<OpenApiInventory | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const hasDocument = document.trim().length >= 2

  const pickFile = async (file: File | undefined) => {
    if (!file) return
    setError('')
    try {
      const text = await file.text()
      setDocument(text)
      setFilename(file.name)
    } catch (e) {
      setError(errorDetail(e))
    }
  }

  const reset = () => {
    setDocument('')
    setFilename(undefined)
    setApplyScope(false)
    setResult(null)
    setError('')
  }

  const run = async () => {
    if (!hasDocument) {
      setError(
        format === 'burp'
          ? 'Paste a Burp XML export or pick a .xml file first.'
          : 'Paste an OpenAPI document or pick a .json/.yaml file first.',
      )
      return
    }
    setLoading(true)
    setError('')
    try {
      const payload = {
        document,
        filename,
        session_id: activeSessionId,
        apply_scope: applyScope,
      }
      const inventory = format === 'burp' ? await importBurp(payload) : await importOpenApi(payload)
      setResult(inventory)
    } catch (e) {
      setResult(null)
      setError(errorDetail(e))
    } finally {
      setLoading(false)
    }
  }

  const rendered = result ? result.endpoints.slice(0, MAX_RENDERED_ENDPOINTS) : []
  const hidden = result ? result.endpoint_count - rendered.length : 0

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-4 overflow-y-auto h-full">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <FileInput size={22} className="text-purple-400 shrink-0" />
          <div>
            <h1 className="text-xl font-bold text-gray-100">Import API</h1>
            <p className="text-xs text-gray-500 mt-0.5">
              An OpenAPI 2.0/3.x document or a Burp XML item export is parsed locally into an
              endpoint inventory. No traffic is sent to the target.
            </p>
          </div>
        </div>
        <button
          onClick={reset}
          className="flex items-center gap-1 px-2 py-1 text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-800 rounded transition-colors"
        >
          <X size={12} /> Clear
        </button>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
        <div className="flex bg-gray-800 rounded-lg overflow-hidden w-fit">
          {(['openapi', 'burp'] as const).map((option) => (
            <button
              key={option}
              onClick={() => {
                setFormat(option)
                setResult(null)
                setError('')
              }}
              className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                format === option ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {option === 'openapi' ? 'OpenAPI' : 'Burp XML'}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 px-3 py-1.5 rounded bg-gray-800 border border-gray-700 text-xs text-gray-300 cursor-pointer hover:border-purple-700 transition-colors">
            <Upload size={13} />
            Choose file
            <input
              key={format}
              type="file"
              accept={format === 'burp' ? '.xml,.burp' : '.json,.yaml,.yml'}
              className="hidden"
              onChange={(e) => pickFile(e.target.files?.[0])}
            />
          </label>
          {filename && <span className="text-xs font-mono text-gray-500 truncate">{filename}</span>}
          <span className="text-[11px] text-gray-600">or paste the document below</span>
        </div>

        <textarea
          value={document}
          onChange={(e) => {
            setDocument(e.target.value)
            if (filename) setFilename(undefined)
          }}
          spellCheck={false}
          placeholder={
            format === 'burp'
              ? '<?xml version="1.0"?>\n<items burpVersion="2024.7.1">\n  <item>\n    <url>https://target.test/api/users</url>\n    ...'
              : 'openapi: 3.0.3\ninfo:\n  title: Example\n  version: "1.0"\npaths:\n  /users:\n    get:\n      summary: List users'
          }
          className="w-full h-56 resize-y bg-gray-950 border border-gray-800 rounded px-3 py-2 text-xs font-mono text-gray-300 placeholder:text-gray-700 focus:outline-none focus:border-purple-700"
        />

        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className={`flex items-center gap-2 text-xs ${activeSessionId ? 'text-gray-300' : 'text-gray-600'}`}>
            <input
              type="checkbox"
              checked={applyScope}
              disabled={!activeSessionId}
              onChange={(e) => setApplyScope(e.target.checked)}
              className="accent-purple-600"
            />
            Add the declared servers to the active session scope (include rules)
            {!activeSessionId && <span className="text-[11px] text-gray-600">— no active session</span>}
          </label>

          <button
            onClick={run}
            disabled={loading || !hasDocument}
            className="flex items-center gap-2 px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-500 disabled:opacity-50 disabled:hover:bg-purple-600 text-xs font-medium text-white transition-colors"
          >
            {loading && <Loader2 size={13} className="animate-spin" />}
            {loading ? 'Parsing…' : 'Import document'}
          </button>
        </div>
      </div>

      {error && (
        <div className="text-xs text-red-300 bg-red-950/30 border border-red-900/40 rounded px-3 py-2">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3">
              <div className="text-[10px] uppercase tracking-wider text-gray-500">Spec</div>
              <div className="text-sm font-medium text-gray-200 mt-1 truncate">
                {result.spec.title || 'Untitled'}
              </div>
              <div className="text-[11px] text-gray-500 font-mono mt-0.5">
                {result.spec.version === 'burp-xml'
                  ? `Burp export${result.item_count ? ` · ${result.item_count} items` : ''}`
                  : `OpenAPI ${result.spec.version} · API ${result.spec.api_version || '—'}`}
                {result.filename ? ` · ${result.filename}` : ''}
              </div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3">
              <div className="text-[10px] uppercase tracking-wider text-gray-500">Endpoints</div>
              <div className="text-2xl font-bold text-gray-100 mt-1">{result.endpoint_count}</div>
              <div className="text-[11px] text-gray-500 mt-0.5">
                {result.servers.length > 0 ? `${result.servers.length} server(s) declared` : 'no server declared'}
              </div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3">
              <div className="text-[10px] uppercase tracking-wider text-gray-500">By method</div>
              <div className="flex flex-wrap gap-1 mt-2">
                {Object.entries(result.method_counts).map(([method, count]) => (
                  <span
                    key={method}
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase ${methodClass(method)}`}
                  >
                    {method} {count}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {result.servers.length > 0 && (
            <div className="text-xs text-gray-500">
              <span className="text-gray-400">Servers:</span>{' '}
              <span className="font-mono">{result.servers.join(', ')}</span>
            </div>
          )}

          {result.scope && (
            <div className="text-xs bg-gray-900 border border-gray-800 rounded px-3 py-2">
              <span className="text-gray-400">Scope:</span>{' '}
              <span className="text-green-400">{result.scope.added.length} include rule(s) added</span>
              {result.scope.skipped.length > 0 && (
                <span className="text-gray-500"> · {result.scope.skipped.length} already present</span>
              )}
              {(result.scope.added.length > 0 || result.scope.skipped.length > 0) && (
                <div className="font-mono text-[11px] text-gray-500 mt-1 truncate">
                  {[...result.scope.added, ...result.scope.skipped.map((h) => `${h} (existing)`)].join(', ')}
                </div>
              )}
            </div>
          )}

          {result.warnings.length > 0 && (
            <div className="space-y-1.5">
              <div className="text-xs font-medium text-gray-300">
                Contract warnings <span className="text-gray-500">({result.warnings.length})</span>
              </div>
              {result.warnings.map((warning, index) => (
                <WarningRow key={`${warning.code}-${index}`} warning={warning} />
              ))}
            </div>
          )}

          {result.endpoints.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
              <div className="max-h-[28rem] overflow-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-gray-950 border-b border-gray-800">
                    <tr className="text-left text-[10px] uppercase tracking-wider text-gray-500">
                      <th className="px-3 py-2 w-20">Method</th>
                      <th className="px-3 py-2">Path</th>
                      <th className="px-3 py-2">Summary</th>
                      <th className="px-3 py-2 w-20">Params</th>
                      <th className="px-3 py-2 w-24">Auth</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rendered.map((endpoint, index) => (
                      <tr
                        key={`${endpoint.method}-${endpoint.path}-${index}`}
                        className="border-b border-gray-800/60 last:border-0 hover:bg-gray-800/30"
                      >
                        <td className="px-3 py-1.5">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase ${methodClass(endpoint.method)}`}>
                            {endpoint.method}
                          </span>
                        </td>
                        <td className="px-3 py-1.5 font-mono text-gray-300 max-w-[22rem] truncate" title={endpoint.url}>
                          {endpoint.path}
                        </td>
                        <td className="px-3 py-1.5 text-gray-500 max-w-[18rem] truncate" title={endpoint.summary || ''}>
                          {endpoint.summary || '—'}
                        </td>
                        <td className="px-3 py-1.5 text-gray-500">{endpoint.parameters.length}</td>
                        <td className="px-3 py-1.5">
                          {endpoint.authenticated ? (
                            <span className="text-amber-400">{endpoint.security.join(', ') || 'yes'}</span>
                          ) : (
                            <span className="text-gray-600">none</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {hidden > 0 && (
                <div className="px-3 py-2 border-t border-gray-800 text-[11px] text-gray-500">
                  Showing the first {MAX_RENDERED_ENDPOINTS} of {result.endpoint_count} endpoints — {hidden} hidden.
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

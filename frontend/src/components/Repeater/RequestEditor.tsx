import { memo, useState, useRef, useEffect, useCallback } from 'react'
import { Send, Loader2 } from 'lucide-react'

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
const BODY_DISABLED_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'])

interface RequestEditorProps {
  method: string
  scheme: string
  url: string
  headers: string
  body: string
  response: any
  loading: boolean
  error: string | null
  onMethodChange: (val: string) => void
  onSchemeChange: (val: string) => void
  onUrlChange: (val: string) => void
  onHeadersChange: (val: string) => void
  onBodyChange: (val: string) => void
  onSend: () => void
}

function getStatusColor(status: number): string {
  if (status >= 200 && status < 300) return 'text-green-400'
  if (status >= 300 && status < 400) return 'text-yellow-400'
  if (status >= 400 && status < 500) return 'text-orange-400'
  if (status >= 500) return 'text-red-400'
  return 'text-gray-400'
}

function prettyPrint(text: string): string {
  if (!text) return ''
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {}
  try {
    const parser = new DOMParser()
    const doc = parser.parseFromString(text, 'text/html')
    if (!doc.querySelector('parsererror')) {
      return doc.documentElement.outerHTML.replace(/>\s*</g, '>\n<')
    }
    const xml = parser.parseFromString(text, 'text/xml')
    if (!xml.querySelector('parsererror')) {
      return xml.documentElement.outerHTML.replace(/>\s*</g, '>\n<')
    }
  } catch {}
  return text
}

function toHex(text: string): string {
  const bytes = new TextEncoder().encode(text)
  const lines: string[] = []
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, i + 16)
    const hex = Array.from(slice).map((b) => b.toString(16).padStart(2, '0')).join(' ')
    const ascii = Array.from(slice).map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('')
    const addr = i.toString(16).padStart(8, '0')
    lines.push(`${addr}  ${hex.padEnd(47)}  ${ascii}`)
  }
  return lines.join('\n')
}

function buildCurl(method: string, url: string, headers: Record<string, string>, body?: string): string {
  const parts = [`curl -X ${method}`, `'${url}'`]
  for (const [k, v] of Object.entries(headers)) {
    if (k.trim()) parts.push(`-H '${k}: ${v}'`)
  }
  if (body && !BODY_DISABLED_METHODS.has(method)) {
    parts.push(`-d '${body.replace(/'/g, "\\'")}'`)
  }
  return parts.join(' \\\n  ')
}

function parseHeaders(headersStr: string): Record<string, string> {
  const obj: Record<string, string> = {}
  headersStr.split('\n').forEach((line) => {
    const idx = line.indexOf(':')
    if (idx > 0) {
      const k = line.slice(0, idx).trim()
      const v = line.slice(idx + 1).trim()
      if (k) obj[k] = v
    }
  })
  return obj
}

export const RequestEditor = memo(function RequestEditor({
  method, scheme, url, headers, body, response, loading, error, onMethodChange, onSchemeChange, onUrlChange, onHeadersChange, onBodyChange, onSend,
}: RequestEditorProps) {
  const [bodyTab, setBodyTab] = useState<'raw' | 'pretty' | 'hex'>('raw')
  const [copied, setCopied] = useState(false)
  const urlRef = useRef<HTMLInputElement>(null)

  const bodyDisabled = BODY_DISABLED_METHODS.has(method)

  useEffect(() => {
    if (!bodyDisabled && body.trim()) {
      let detected: string | null = null
      try {
        JSON.parse(body)
        detected = 'application/json'
      } catch { /* not json */ }
      if (body.trim().startsWith('<')) detected = 'application/xml'
      if (body.trim().startsWith('<?xml')) detected = 'application/xml'
      if (detected) {
        const hdrs = parseHeaders(headers)
        if (!hdrs['Content-Type']) {
          const newHdrs = headers ? headers + '\n' : ''
          onHeadersChange(newHdrs + `Content-Type: ${detected}`)
        }
      }
    }
  }, [body])

  const handleCopyCurl = useCallback(() => {
    const hdrs = parseHeaders(headers)
    const curl = buildCurl(method, url, hdrs, body)
    navigator.clipboard.writeText(curl)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [method, url, headers, body])

  const responseHeaders: [string, string][] = response?.headers ? Object.entries(response.headers as Record<string, string>) : []

  return (
    <div className="flex flex-1 min-h-0">
      <div className="flex-1 flex flex-col border-r border-gray-800 min-w-0">
        <div className="flex gap-1.5 p-2 border-b border-gray-800 items-center">
          <select
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 w-24 shrink-0"
            value={method}
            onChange={(e) => onMethodChange(e.target.value)}
          >
            {METHODS.map((m) => (
              <option key={m}>{m}</option>
            ))}
          </select>
          <div className="flex items-center bg-gray-800 border border-gray-700 rounded flex-1 min-w-0">
            <select
              className="bg-transparent text-xs text-gray-400 pl-2 pr-0 py-1 outline-none cursor-pointer shrink-0"
              value={scheme}
              onChange={(e) => onSchemeChange(e.target.value)}
            >
              <option value="http">http://</option>
              <option value="https">https://</option>
            </select>
            <input
              ref={urlRef}
              className="flex-1 bg-transparent text-xs text-gray-200 py-1 pr-2 outline-none min-w-0"
              placeholder="target.com/api/endpoint"
              value={url}
              onChange={(e) => onUrlChange(e.target.value)}
            />
          </div>
          <button
            className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium disabled:opacity-50 flex items-center gap-1 shrink-0"
            onClick={onSend}
            disabled={loading || !url}
          >
            <Send className="w-3 h-3" />
            {loading ? 'Sending...' : 'Send'}
          </button>
        </div>
        <div className="text-xs text-gray-400 px-2 py-1 border-b border-gray-800 bg-gray-800/50 select-none">Headers</div>
        <textarea
          className="flex-[2] bg-gray-900 text-xs font-mono text-gray-300 p-2 resize-none outline-none min-h-0"
          placeholder="Content-Type: application/json"
          value={headers}
          onChange={(e) => onHeadersChange(e.target.value)}
          spellCheck={false}
        />
        <div className="border-t border-gray-800" />
        <div className="text-xs text-gray-400 px-2 py-1 border-b border-gray-800 bg-gray-800/50 select-none">Body</div>
        <textarea
          className="flex-[3] bg-gray-900 text-xs font-mono text-gray-300 p-2 resize-none outline-none min-h-0"
          placeholder='{"key": "value"}'
          value={body}
          onChange={(e) => onBodyChange(e.target.value)}
          disabled={bodyDisabled}
          spellCheck={false}
        />
      </div>
      <div className="flex-1 flex flex-col min-w-0">
        {loading && (
          <div className="flex items-center justify-center gap-2 p-4 text-gray-400 text-xs border-b border-gray-800">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            Sending request...
          </div>
        )}
        {error && (
          <div className="text-red-400 text-xs p-2 border-b border-gray-800">{error}</div>
        )}
        {response ? (
          <>
              <div className="flex items-center gap-2 px-2 py-1.5 border-b border-gray-800 bg-gray-800/50">
              <span className={`text-xs font-bold ${getStatusColor(response.status)}`}>
                {response.status}
              </span>
              <span className="text-xs text-gray-400">{response.time_ms}ms</span>
              <span className="text-xs text-gray-600">|</span>
              <span className="text-xs text-gray-500">{(response.body || '').length} bytes</span>
              <div className="flex-1" />
              <button
                className="text-xs text-gray-400 hover:text-gray-200 transition-colors"
                onClick={() => {
                  navigator.clipboard.writeText(response.body || '')
                }}
              >
                Copy body
              </button>
              <button
                className="text-xs text-gray-400 hover:text-gray-200 transition-colors"
                onClick={handleCopyCurl}
              >
                {copied ? 'Copied!' : 'Copy as curl'}
              </button>
            </div>
            <div className="text-xs text-gray-400 px-2 py-1 border-b border-gray-800 select-none">
              Response Headers
            </div>
            <div className="max-h-24 overflow-y-auto bg-gray-900 border-b border-gray-800">
              {responseHeaders.length === 0 && (
                <div className="text-xs text-gray-500 p-2">No headers</div>
              )}
              {responseHeaders.map(([k, v]) => (
                <div key={k} className="text-xs font-mono text-gray-300 px-2 py-0.5">
                  <span className="text-gray-500">{k}:</span> {v}
                </div>
              ))}
            </div>
              <div className="flex border-b border-gray-800 bg-gray-800/50">
              {(['raw', 'pretty', 'hex'] as const).map((tab) => (
                <button
                  key={tab}
                  className={`text-xs px-3 py-1 border-r border-gray-800 transition-colors ${
                    bodyTab === tab ? 'text-purple-400 bg-gray-800' : 'text-gray-400 hover:text-gray-200'
                  }`}
                  onClick={() => setBodyTab(tab)}
                >
                  {tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </div>
            <pre className="flex-1 text-xs font-mono text-gray-300 p-2 overflow-auto whitespace-pre-wrap break-all">
              {bodyTab === 'raw' && (response.body || '')}
              {bodyTab === 'pretty' && prettyPrint(response.body || '')}
              {bodyTab === 'hex' && toHex(response.body || '')}
            </pre>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-xs text-gray-500">
            Send a request to see the response
          </div>
        )}
      </div>
    </div>
  )
})

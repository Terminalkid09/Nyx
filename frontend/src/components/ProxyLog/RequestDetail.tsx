import { useState } from 'react'
import { NyxRequest } from '../../types'
import { useProxyStore } from '../../store/useProxyStore'

interface Props {
  request: NyxRequest
}

type Tab = 'request' | 'response'

export function RequestDetail({ request }: Props) {
  const [tab, setTab] = useState<Tab>('request')
  const select = useProxyStore((s) => s.select)

  const formatHeaders = (headers: Record<string, string> | null) => {
    if (!headers) return '(no headers)'
    return Object.entries(headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n')
  }

  const requestRaw = `${request.method} ${request.path} ${request.http_version}\n${formatHeaders(request.request_headers)}\n\n${request.request_body ?? ''}`

  const responseRaw = request.response_status
    ? `HTTP/1.1 ${request.response_status} ${request.response_reason ?? ''}\n${formatHeaders(request.response_headers)}\n\n${request.response_body ?? ''}`
    : '(waiting for response...)'

  return (
    <div className="flex flex-col h-full bg-gray-900">
      <div className="flex items-center border-b border-gray-800">
        <button
          className={`px-4 py-2 text-xs font-medium ${
            tab === 'request' ? 'text-purple-400 border-b-2 border-purple-500' : 'text-gray-400'
          }`}
          onClick={() => setTab('request')}
        >
          Request
        </button>
        <button
          className={`px-4 py-2 text-xs font-medium ${
            tab === 'response' ? 'text-purple-400 border-b-2 border-purple-500' : 'text-gray-400'
          }`}
          onClick={() => setTab('response')}
        >
          Response
        </button>
        <div className="flex-1" />
        <button
          onClick={() => select(null)}
          className="px-3 py-2 text-xs text-gray-500 hover:text-white transition-colors"
          title="Close"
        >
          ✕
        </button>
      </div>
      <div className="flex-1 overflow-auto p-4">
        <pre className="text-xs font-mono text-gray-300 whitespace-pre-wrap">
          {tab === 'request' ? requestRaw : responseRaw}
        </pre>
      </div>
      <div className="p-2 border-t border-gray-800 text-xs text-gray-500 flex gap-4">
        <span>URL: {request.url}</span>
        {request.response_time_ms != null && (
          <span>Time: {request.response_time_ms}ms</span>
        )}
        {request.response_size_bytes != null && (
          <span>Size: {(request.response_size_bytes / 1024).toFixed(1)}KB</span>
        )}
      </div>
    </div>
  )
}

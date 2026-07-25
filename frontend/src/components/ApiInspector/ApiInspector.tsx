import { useState, useEffect } from 'react'
import { apiClient } from '../../api/client'
import { NyxRequest } from '../../types'

export function ApiInspector() {
  const [requests, setRequests] = useState<NyxRequest[]>([])
  const [filter, setFilter] = useState<string>('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    apiClient.get('/api/api-inspector/requests').then(({ data }) => {
      setRequests(data)
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  const filtered = filter
    ? requests.filter((r) => r.api_type === filter)
    : requests

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300">API Inspector</div>
      <div className="flex gap-2 p-2 border-b border-gray-800">
        {['', 'rest', 'graphql', 'grpc'].map((t) => (
          <button
            key={t}
            onClick={() => setFilter(t)}
            className={`px-2 py-1 rounded text-xs ${
              filter === t ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400'
            }`}
          >
            {t || 'All'}
          </button>
        ))}
        <span className="ml-auto text-gray-500 text-xs">{filtered.length} requests</span>
      </div>
      <div className="flex-1 overflow-auto">
        {loading ? (
          <div className="text-gray-500 text-xs p-4">Loading...</div>
        ) : (
          filtered.map((r) => (
            <div key={r.id} className="px-3 py-2 border-b border-gray-900 hover:bg-gray-800">
              <div className="flex items-center gap-2">
                <span className="text-purple-400 font-mono text-xs font-bold">{r.method}</span>
                <span className="text-xs text-gray-300 truncate flex-1">{r.url}</span>
                <span className={`text-xs px-1 rounded ${
                  r.api_type === 'rest' ? 'text-blue-400' :
                  r.api_type === 'graphql' ? 'text-pink-400' :
                  'text-orange-400'
                }`}>{r.api_type}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

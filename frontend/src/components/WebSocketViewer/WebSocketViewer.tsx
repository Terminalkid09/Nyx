import { useState, useEffect } from 'react'
import { Globe, ArrowUpRight, ArrowDownLeft, Trash2 } from 'lucide-react'
import { fetchWebSocketMessages, deleteWebSocketMessage } from '../../api/endpoints/websocketMessages'
import { WebSocketMsg } from '../../types'

export function WebSocketViewer() {
  const [messages, setMessages] = useState<WebSocketMsg[]>([])
  const [sessionIds, setSessionIds] = useState<string[]>([])
  const [selectedSession, setSelectedSession] = useState('')
  const [requestId, setRequestId] = useState('')
  const [selectedMsg, setSelectedMsg] = useState<WebSocketMsg | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const loadMessages = () => {
    setLoading(true)
    setError('')
    fetchWebSocketMessages(selectedSession || undefined, requestId || undefined)
      .then((data) => {
        setMessages(data)
        const ids = [...new Set(data.map((m) => m.session_id))]
        setSessionIds((prev) => {
          const merged = new Set([...prev, ...ids])
          return Array.from(merged)
        })
        setLoading(false)
      })
      .catch((err: any) => {
        setError(err.response?.data?.detail || err.message)
        setLoading(false)
      })
  }

  useEffect(() => { loadMessages() }, [])

  const handleDelete = async (id: string) => {
    try {
      await deleteWebSocketMessage(id)
      setMessages((prev) => prev.filter((m) => m.id !== id))
      if (selectedMsg?.id === id) setSelectedMsg(null)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const truncatePayload = (payload: string | null, max = 100) => {
    if (!payload) return '(empty)'
    return payload.length > max ? payload.slice(0, max) + '...' : payload
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <Globe size={16} />
        <span>WebSocket Viewer</span>
      </div>
      <div className="flex gap-2 p-2 border-b border-gray-800 items-center">
        <select
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
          value={selectedSession}
          onChange={(e) => setSelectedSession(e.target.value)}
        >
          <option value="">All Sessions</option>
          {sessionIds.map((sid) => (
            <option key={sid} value={sid}>{sid.slice(0, 8)}...</option>
          ))}
        </select>
        <input
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 w-40"
          placeholder="Request ID..."
          value={requestId}
          onChange={(e) => setRequestId(e.target.value)}
        />
        <button
          onClick={loadMessages}
          className="bg-purple-600 hover:bg-purple-700 px-2 py-1 rounded text-xs font-medium"
        >
          Filter
        </button>
        <span className="ml-auto text-gray-500 text-xs">{messages.length} messages</span>
      </div>
      <div className="flex-1 overflow-auto">
        {error && <div className="text-xs text-red-400 p-2">{error}</div>}
        {loading ? (
          <div className="text-xs text-gray-500 p-4">Loading...</div>
        ) : messages.length === 0 ? (
          <div className="text-xs text-gray-500 p-4">No WebSocket messages captured.</div>
        ) : (
          <div className="flex flex-col h-full">
            <div className="overflow-auto flex-1">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500 sticky top-0 bg-gray-950">
                    <th className="text-left px-3 py-2 font-medium">Direction</th>
                    <th className="text-left px-3 py-2 font-medium">Timestamp</th>
                    <th className="text-left px-3 py-2 font-medium">Payload</th>
                    <th className="text-right px-3 py-2 font-medium">Size</th>
                    <th className="text-right px-3 py-2 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {messages.map((msg) => (
                    <tr
                      key={msg.id}
                      className={`border-b border-gray-900 cursor-pointer hover:bg-gray-800 ${
                        selectedMsg?.id === msg.id ? 'bg-gray-800' : ''
                      }`}
                      onClick={() => setSelectedMsg(msg)}
                    >
                      <td className="px-3 py-2">
                        {msg.direction === 'sent' ? (
                          <span className="inline-flex items-center gap-1 text-xs text-blue-400 font-medium">
                            <ArrowUpRight size={12} /> Sent
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs text-green-400 font-medium">
                            <ArrowDownLeft size={12} /> Received
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-gray-400 font-mono">
                        {new Date(msg.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-3 py-2 text-gray-300 font-mono truncate max-w-xs">
                        {truncatePayload(msg.payload)}
                      </td>
                      <td className="px-3 py-2 text-right text-gray-400">
                        {msg.payload_size > 1024
                          ? `${(msg.payload_size / 1024).toFixed(1)}KB`
                          : `${msg.payload_size}B`}
                      </td>
                      <td className="px-3 py-2 text-right">
                        <button
                          onClick={(e) => { e.stopPropagation(); handleDelete(msg.id) }}
                          className="p-1 text-red-400 hover:text-red-300"
                          title="Delete"
                        >
                          <Trash2 size={12} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {selectedMsg && (
              <div className="border-t border-gray-800 p-3 bg-gray-900 max-h-64 overflow-auto">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xs font-medium text-gray-400">Full Payload</span>
                  <span className="text-xs text-gray-600">
                    {new Date(selectedMsg.timestamp).toLocaleString()}
                  </span>
                  <span className="text-xs text-gray-600 ml-auto">
                    {selectedMsg.is_binary ? 'Binary' : 'Text'} · {selectedMsg.payload_size}B
                  </span>
                </div>
                <pre className="text-xs font-mono text-gray-300 whitespace-pre-wrap break-all">
                  {selectedMsg.payload || '(empty)'}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

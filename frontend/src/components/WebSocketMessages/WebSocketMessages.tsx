import { useState, useEffect } from 'react'
import { Globe, Trash2, RefreshCw, Binary } from 'lucide-react'
import { listWSMessages, deleteWSMessage, WSMessage } from '../../api/endpoints/wsMessages'

export function WebSocketMessages() {
  const [messages, setMessages] = useState<WSMessage[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<string | null>(null)

  const fetch = async () => { setLoading(true); try { setMessages(await listWSMessages()) } catch {} finally { setLoading(false) } }
  useEffect(() => { fetch() }, [])

  const handleDelete = async (id: string) => { await deleteWSMessage(id); setMessages(messages.filter(m => m.id !== id)) }

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Globe className="w-6 h-6 text-purple-400" />
          <h1 className="text-xl font-bold text-gray-100">WebSocket Messages</h1>
        </div>
        <button onClick={fetch} className="p-2 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors"><RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /></button>
      </div>

      {loading ? (
        <div className="text-center py-12 text-gray-500">Loading...</div>
      ) : messages.length === 0 ? (
        <div className="text-center py-12 text-gray-500">No WebSocket messages captured.</div>
      ) : (
        <div className="space-y-2">
          {messages.map(m => (
            <div key={m.id} className="bg-gray-900 border border-gray-800 rounded-lg">
              <div className="px-5 py-3 flex items-center justify-between cursor-pointer" onClick={() => setSelected(selected === m.id ? null : m.id)}>
                <div className="flex items-center gap-3">
                  <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border ${m.direction === 'sent' ? 'text-green-400 bg-green-900/30 border-green-800' : m.direction === 'received' ? 'text-blue-400 bg-blue-900/30 border-blue-800' : 'text-yellow-400 bg-yellow-900/30 border-yellow-800'}`}>{m.direction}</span>
                  <div>
                    <span className="text-xs text-gray-400">{m.is_binary ? <Binary className="w-3 h-3 inline" /> : 'text'}</span>
                    <span className="ml-2 text-xs text-gray-500">{m.payload_size} bytes</span>
                    <span className="ml-2 text-xs text-gray-600">{new Date(m.timestamp).toLocaleString()}</span>
                  </div>
                </div>
                <button onClick={e => { e.stopPropagation(); handleDelete(m.id) }} className="p-1.5 rounded hover:bg-gray-800 text-gray-500 hover:text-red-400 transition-colors"><Trash2 className="w-4 h-4" /></button>
              </div>
              {selected === m.id && m.payload && (
                <div className="px-5 pb-4 pt-0 border-t border-gray-800">
                  <pre className="text-xs text-gray-400 font-mono mt-3 whitespace-pre-wrap overflow-x-auto max-h-64">{m.payload}</pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

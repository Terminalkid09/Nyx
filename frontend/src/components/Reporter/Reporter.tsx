import { useState } from 'react'
import { apiClient } from '../../api/client'
import { useSessionStore } from '../../store/useSessionStore'

export function Reporter() {
  const { sessions, activeSessionId } = useSessionStore()
  const [selectedSession, setSelectedSession] = useState(activeSessionId || '')
  const [format, setFormat] = useState('html')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const generateReport = async () => {
    if (!selectedSession) return
    setLoading(true)
    setError('')
    try {
      const { data, headers } = await apiClient.post('/api/reports/generate', null, {
        params: { session_id: selectedSession, format },
        responseType: format === 'pdf' ? 'blob' : 'text',
      })

      const ext = format === 'pdf' ? 'pdf' : format
      const mime = format === 'json' ? 'application/json' : format === 'md' ? 'text/markdown' : 'text/html'
      const blob = format === 'pdf' ? data : new Blob([data], { type: mime })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `nyx-report-${selectedSession.slice(0, 8)}.${ext}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300">Reporter</div>
      <div className="flex-1 p-4 space-y-4">
        <div>
          <label className="text-xs text-gray-500 block mb-1">Session</label>
          <select
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
            value={selectedSession}
            onChange={(e) => setSelectedSession(e.target.value)}
          >
            <option value="">Select a session...</option>
            {sessions.map((s) => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
        </div>

        <div>
          <label className="text-xs text-gray-500 block mb-1">Format</label>
          <div className="flex gap-2">
            {['html', 'pdf', 'json', 'md'].map((f) => (
              <button
                key={f}
                onClick={() => setFormat(f)}
                className={`px-3 py-1 rounded text-xs ${
                  format === f ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400'
                }`}
              >
                {f.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        <button
          className="bg-purple-600 hover:bg-purple-700 px-4 py-1 rounded text-xs font-medium disabled:opacity-50"
          onClick={generateReport}
          disabled={loading || !selectedSession}
        >
          {loading ? 'Generating...' : 'Generate Report'}
        </button>

        {error && <div className="text-red-400 text-xs">{error}</div>}
      </div>
    </div>
  )
}

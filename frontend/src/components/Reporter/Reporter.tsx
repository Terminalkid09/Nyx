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
      // Always a blob: the server decides the real format, and a PDF that the
      // backend cannot render answers 400 — with a blob response axios would
      // otherwise turn that error body into "[object Blob]".
      const response = await apiClient.post('/api/reports/generate', null, {
        params: { session_id: selectedSession, format },
        responseType: 'blob',
      })

      const blob = response.data as Blob
      const disposition = String(response.headers?.['content-disposition'] || '')
      const match = disposition.match(/filename="?([^";]+)"?/)
      const filename = match ? match[1] : `nyx-report-${selectedSession.slice(0, 8)}.${format}`

      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
    } catch (err: any) {
      let detail = err.response?.data?.detail
      if (err.response?.data instanceof Blob) {
        try {
          detail = JSON.parse(await err.response.data.text())?.detail
        } catch { /* keep the generic message */ }
      }
      setError(detail || err.message)
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

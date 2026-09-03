import { Radio } from 'lucide-react'
import { useProxyStore } from '../../store/useProxyStore'

interface Props {
  captureActive: boolean
  onToggleCapture: () => void
}

export function FilterBar({ captureActive, onToggleCapture }: Props) {
  const { filter, setFilter, requests } = useProxyStore()

  return (
    <div className="flex gap-2 p-2 border-b border-gray-800 items-center">
      <input
        className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs w-48 text-gray-200"
        placeholder="Search URL..."
        value={filter.search || ''}
        onChange={(e) => setFilter({ search: e.target.value })}
      />
      <select
        className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
        value={filter.method || ''}
        onChange={(e) => setFilter({ method: e.target.value || undefined })}
      >
        <option value="">All methods</option>
        {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map((m) => (
          <option key={m}>{m}</option>
        ))}
      </select>
      <span className="text-gray-500 text-xs">
        {requests.length} requests
      </span>
      <div className="flex-1" />
      <button
        onClick={onToggleCapture}
        title={captureActive ? 'Capturing traffic — click to pause' : 'Capture paused — click to resume'}
        className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] font-bold transition-colors ${
          captureActive ? 'bg-green-600/20 text-green-400 hover:bg-green-600/30' : 'bg-gray-700/50 text-gray-500 hover:bg-gray-700'
        }`}
      >
        <Radio size={12} className={captureActive ? 'text-green-400 animate-pulse' : ''} />
        {captureActive ? 'Capture ON' : 'Capture OFF'}
      </button>
    </div>
  )
}

import { useProxyStore } from '../../store/useProxyStore'

export function FilterBar() {
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
      <span className="ml-auto text-gray-500 text-xs">
        {requests.length} requests
      </span>
    </div>
  )
}

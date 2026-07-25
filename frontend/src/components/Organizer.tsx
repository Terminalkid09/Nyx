import { useState, useEffect } from 'react'
import { apiClient } from '../api/client'

interface RequestSummary {
  id: string
  method: string
  url: string
  status: number | null
}

interface OrganizerItem {
  id: string
  session_id: string
  request_id: string | null
  created_at: string
  title: string
  notes: string | null
  tags: string[]
  color: string | null
  is_flagged: boolean
  request: RequestSummary | null
}

const COLORS = [
  { value: '', label: 'None', class: '' },
  { value: 'red', label: 'Red', class: 'bg-red-500' },
  { value: 'blue', label: 'Blue', class: 'bg-blue-500' },
  { value: 'green', label: 'Green', class: 'bg-green-500' },
  { value: 'yellow', label: 'Yellow', class: 'bg-yellow-500' },
  { value: 'purple', label: 'Purple', class: 'bg-purple-500' },
]

export function Organizer() {
  const [items, setItems] = useState<OrganizerItem[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [activeTag, setActiveTag] = useState<string | null>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [editNotes, setEditNotes] = useState('')
  const [newTitle, setNewTitle] = useState('')
  const [newUrl, setNewUrl] = useState('')
  const [newColor, setNewColor] = useState('')

  const fetchItems = () => {
    setLoading(true)
    apiClient.get('/api/organizer/').then(({ data }) => {
      setItems(data)
      setLoading(false)
    }).catch(() => setLoading(false))
  }

  useEffect(() => { fetchItems() }, [])

  const allTags = [...new Set(items.flatMap(i => i.tags))]

  const filtered = items.filter(item => {
    if (activeTag && !item.tags.includes(activeTag)) return false
    if (search) {
      const q = search.toLowerCase()
      const matchesTitle = item.title.toLowerCase().includes(q)
      const matchesUrl = item.request?.url.toLowerCase().includes(q)
      const matchesNotes = item.notes?.toLowerCase().includes(q)
      const matchesTags = item.tags.some(t => t.toLowerCase().includes(q))
      if (!matchesTitle && !matchesUrl && !matchesNotes && !matchesTags) return false
    }
    return true
  })

  const handleDelete = async (id: string) => {
    await apiClient.delete(`/api/organizer/${id}`)
    setItems(prev => prev.filter(i => i.id !== id))
  }

  const handleDuplicate = async (id: string) => {
    const { data } = await apiClient.post(`/api/organizer/${id}/duplicate`)
    setItems(prev => [data, ...prev])
  }

  const handleSaveNotes = async (id: string) => {
    await apiClient.put(`/api/organizer/${id}`, { notes: editNotes })
    setItems(prev => prev.map(i => i.id === id ? { ...i, notes: editNotes } : i))
  }

  const handleColorChange = async (id: string, color: string) => {
    await apiClient.put(`/api/organizer/${id}`, { color })
    setItems(prev => prev.map(i => i.id === id ? { ...i, color } : i))
  }

  const handleToggleFlag = async (id: string, is_flagged: boolean) => {
    await apiClient.put(`/api/organizer/${id}`, { is_flagged })
    setItems(prev => prev.map(i => i.id === id ? { ...i, is_flagged } : i))
  }

  const handleAddItem = async () => {
    if (!newTitle.trim()) return
    const session_id = '00000000-0000-0000-0000-000000000001'
    const { data } = await apiClient.post('/api/organizer/', {
      session_id,
      title: newTitle.trim(),
      notes: newUrl.trim() || null,
      color: newColor || null,
      tags: [],
    })
    setItems(prev => [data, ...prev])
    setNewTitle('')
    setNewUrl('')
    setNewColor('')
  }

  const expandItem = (item: OrganizerItem) => {
    if (expandedId === item.id) {
      setExpandedId(null)
      return
    }
    setExpandedId(item.id)
    setEditNotes(item.notes || '')
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300">Organizer</div>

      <div className="p-2 border-b border-gray-800 flex gap-2 items-center">
        <input
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 w-48"
          placeholder="Search..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <div className="flex gap-1 ml-2">
          <button
            onClick={() => setActiveTag(null)}
            className={`px-2 py-0.5 rounded text-xs ${!activeTag ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400'}`}
          >
            All
          </button>
          {allTags.map(tag => (
            <button
              key={tag}
              onClick={() => setActiveTag(activeTag === tag ? null : tag)}
              className={`px-2 py-0.5 rounded text-xs ${activeTag === tag ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400'}`}
            >
              {tag}
            </button>
          ))}
        </div>
        <span className="ml-auto text-gray-500 text-xs">{filtered.length} items</span>
      </div>

      <div className="p-2 border-b border-gray-800 flex gap-2 items-center">
        <input
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 flex-1"
          placeholder="Title..."
          value={newTitle}
          onChange={e => setNewTitle(e.target.value)}
        />
        <input
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 w-64"
          placeholder="URL (optional)"
          value={newUrl}
          onChange={e => setNewUrl(e.target.value)}
        />
        <select
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
          value={newColor}
          onChange={e => setNewColor(e.target.value)}
        >
          {COLORS.map(c => (
            <option key={c.value} value={c.value}>{c.label}</option>
          ))}
        </select>
        <button
          onClick={handleAddItem}
          className="px-3 py-1 rounded text-xs bg-purple-600 text-white hover:bg-purple-500"
        >
          Add
        </button>
      </div>

      <div className="flex-1 overflow-auto">
        {loading ? (
          <div className="text-gray-500 text-xs p-4">Loading...</div>
        ) : (
          filtered.map(item => (
            <div key={item.id}>
              <div
                className="flex items-center gap-2 px-3 py-2 border-b border-gray-900 hover:bg-gray-800 cursor-pointer"
                onClick={() => expandItem(item)}
              >
                <div className={`w-3 h-3 rounded-full flex-shrink-0 ${item.color ? COLORS.find(c => c.value === item.color)?.class || 'bg-gray-700' : 'bg-gray-700'}`} />
                <span className="text-xs text-gray-300 truncate flex-1">{item.title}</span>
                {item.request && (
                  <span className="text-xs text-gray-500 truncate max-w-[200px]">{item.request.url}</span>
                )}
                <div className="flex gap-1">
                  {item.tags.map(tag => (
                    <span key={tag} className="text-xs bg-gray-800 text-gray-400 px-1 rounded">{tag}</span>
                  ))}
                </div>
                {item.is_flagged && <span className="text-xs text-red-400">!</span>}
                <span className="text-xs text-gray-600">{new Date(item.created_at).toLocaleDateString()}</span>
              </div>

              {expandedId === item.id && (
                <div className="px-6 py-2 bg-gray-900 border-b border-gray-800">
                  <div className="flex gap-2 mb-2">
                    {COLORS.map(c => (
                      <button
                        key={c.value}
                        onClick={() => handleColorChange(item.id, c.value)}
                        className={`w-4 h-4 rounded-full ${c.class || 'bg-gray-700 border border-gray-600'} ${item.color === c.value ? 'ring-2 ring-purple-400' : ''}`}
                        title={c.label}
                      />
                    ))}
                    <button
                      onClick={() => handleToggleFlag(item.id, !item.is_flagged)}
                      className={`px-2 py-0.5 rounded text-xs ${item.is_flagged ? 'bg-red-700 text-white' : 'bg-gray-800 text-gray-400'}`}
                    >
                      {item.is_flagged ? 'Flagged' : 'Flag'}
                    </button>
                    <button
                      onClick={() => handleDuplicate(item.id)}
                      className="px-2 py-0.5 rounded text-xs bg-gray-800 text-gray-400 hover:text-white"
                    >
                      Duplicate
                    </button>
                    <button
                      onClick={() => handleDelete(item.id)}
                      className="px-2 py-0.5 rounded text-xs bg-gray-800 text-red-400 hover:bg-red-800 hover:text-white ml-auto"
                    >
                      Delete
                    </button>
                  </div>
                  <textarea
                    className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 resize-none"
                    rows={4}
                    value={editNotes}
                    onChange={e => setEditNotes(e.target.value)}
                    placeholder="Notes..."
                  />
                  <button
                    onClick={() => handleSaveNotes(item.id)}
                    className="mt-1 px-3 py-1 rounded text-xs bg-purple-600 text-white hover:bg-purple-500"
                  >
                    Save Notes
                  </button>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  )
}

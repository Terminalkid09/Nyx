import { useState, useEffect } from 'react'
import { FileText, Plus, Trash2, ChevronDown, ChevronRight } from 'lucide-react'
import { listPolicies, createPolicy, deletePolicy, ScanPolicy } from '../../api/endpoints/scanPolicies'

export function ScanPolicies() {
  const [policies, setPolicies] = useState<ScanPolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')

  useEffect(() => { listPolicies().then(setPolicies).catch(() => {}).finally(() => setLoading(false)) }, [])

  const handleCreate = async () => {
    if (!name) return
    const p = await createPolicy({ name, description: desc, priority: 5, config: { passive_scan: { enabled: true }, active_scan: { enabled: true, max_checks: 50 }, crawl: { max_pages: 50 } } })
    setPolicies([...policies, p]); setShowForm(false); setName(''); setDesc('')
  }

  const handleDelete = async (id: string) => {
    await deletePolicy(id); setPolicies(policies.filter(p => p.id !== id))
  }

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileText className="w-6 h-6 text-purple-400" />
          <h1 className="text-xl font-bold text-gray-100">Scan Policies</h1>
        </div>
        <button onClick={() => setShowForm(!showForm)} className="bg-purple-600 hover:bg-purple-700 px-3 py-1.5 rounded text-xs font-medium text-white flex items-center gap-1.5 transition-colors"><Plus className="w-3.5 h-3.5" /> New Policy</button>
      </div>

      {showForm && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
          <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600" value={name} onChange={e => setName(e.target.value)} placeholder="Policy name" />
          <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600" value={desc} onChange={e => setDesc(e.target.value)} placeholder="Description" />
          <button onClick={handleCreate} className="bg-purple-600 hover:bg-purple-700 px-4 py-1.5 rounded text-xs font-medium text-white transition-colors">Create</button>
        </div>
      )}

      {loading ? (
        <div className="text-center py-12 text-gray-500">Loading...</div>
      ) : (
        <div className="space-y-2">
          {policies.map(p => (
            <div key={p.id} className="bg-gray-900 border border-gray-800 rounded-lg">
              <div className="px-5 py-3 flex items-center justify-between cursor-pointer" onClick={() => setExpanded(expanded === p.id ? null : p.id)}>
                <div className="flex items-center gap-3">
                  {expanded === p.id ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                  <div>
                    <span className="text-sm font-medium text-gray-200">{p.name}</span>
                    <span className="ml-2 text-xs text-gray-500">(priority {p.priority})</span>
                    <p className="text-xs text-gray-500 mt-0.5">{p.description}</p>
                  </div>
                </div>
                <button onClick={e => { e.stopPropagation(); handleDelete(p.id) }} className="p-1.5 rounded hover:bg-gray-800 text-gray-500 hover:text-red-400 transition-colors"><Trash2 className="w-4 h-4" /></button>
              </div>
              {expanded === p.id && (
                <div className="px-5 pb-4 pt-0 border-t border-gray-800">
                  <pre className="text-xs text-gray-400 font-mono mt-3 whitespace-pre-wrap">{JSON.stringify(p.config, null, 2)}</pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

import { useState, useEffect } from 'react'
import { Puzzle, Plus, ToggleLeft, ToggleRight, Trash2, RefreshCw } from 'lucide-react'
import { listPlugins, registerPlugin, togglePlugin, deletePlugin, reloadPlugins, PluginItem } from '../../api/endpoints/plugins'

export function Plugins() {
  const [plugins, setPlugins] = useState<PluginItem[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [name, setName] = useState('')
  const [path, setPath] = useState('')
  const [hookType, setHookType] = useState('request')

  const fetch = async () => { setLoading(true); try { setPlugins(await listPlugins()) } catch {} finally { setLoading(false) } }
  useEffect(() => { fetch() }, [])

  const handleRegister = async () => {
    if (!name || !path) return
    await registerPlugin({ name, path, hook_type: hookType })
    setShowForm(false); setName(''); setPath(''); setHookType('request')
    await fetch()
  }

  const handleToggle = async (id: string) => { await togglePlugin(id); await fetch() }
  const handleDelete = async (id: string) => { await deletePlugin(id); await fetch() }
  const handleReload = async () => { await reloadPlugins(); await fetch() }

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Puzzle className="w-6 h-6 text-purple-400" />
          <h1 className="text-xl font-bold text-gray-100">Plugins</h1>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={handleReload} className="p-2 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors" title="Reload all"><RefreshCw className="w-4 h-4" /></button>
          <button onClick={() => setShowForm(!showForm)} className="bg-purple-600 hover:bg-purple-700 px-3 py-1.5 rounded text-xs font-medium text-white flex items-center gap-1.5 transition-colors"><Plus className="w-3.5 h-3.5" /> Register</button>
        </div>
      </div>

      {showForm && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600" value={name} onChange={e => setName(e.target.value)} placeholder="Plugin name" />
            <input className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600" value={path} onChange={e => setPath(e.target.value)} placeholder="Path (in plugins/)" />
            <select className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" value={hookType} onChange={e => setHookType(e.target.value)}>
              <option value="request">request</option>
              <option value="response">response</option>
              <option value="both">both</option>
            </select>
          </div>
          <button onClick={handleRegister} className="bg-purple-600 hover:bg-purple-700 px-4 py-1.5 rounded text-xs font-medium text-white transition-colors">Register Plugin</button>
        </div>
      )}

      {loading ? (
        <div className="text-center py-12 text-gray-500">Loading...</div>
      ) : plugins.length === 0 ? (
        <div className="text-center py-12 text-gray-500">No plugins registered.</div>
      ) : (
        <div className="space-y-2">
          {plugins.map(p => (
            <div key={p.id} className="bg-gray-900 border border-gray-800 rounded-lg px-5 py-3 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <Puzzle className="w-5 h-5 text-gray-500" />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-200">{p.name}</span>
                    <span className="text-[10px] text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">{p.hook_type}</span>
                    <span className="text-[10px] text-gray-500">v{p.version}</span>
                  </div>
                  <p className="text-xs text-gray-500 mt-0.5">{p.description || p.path}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => handleToggle(p.id)} className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors" title={p.enabled ? 'Disable' : 'Enable'}>
                  {p.enabled ? <ToggleRight className="w-4 h-4 text-green-400" /> : <ToggleLeft className="w-4 h-4 text-gray-500" />}
                </button>
                <button onClick={() => handleDelete(p.id)} className="p-1.5 rounded hover:bg-gray-800 text-gray-500 hover:text-red-400 transition-colors" title="Uninstall"><Trash2 className="w-4 h-4" /></button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

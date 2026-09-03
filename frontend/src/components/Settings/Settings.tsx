import { useState, useEffect } from 'react'
import { Settings2, Save } from 'lucide-react'
import { getAllSettings, updateProxySettings, AllSettings } from '../../api/endpoints/settings'

export function Settings() {
  const [settings, setSettings] = useState<AllSettings | null>(null)
  const [host, setHost] = useState('')
  const [port, setPort] = useState(8080)
  const [mode, setMode] = useState('regular')
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState('')

  useEffect(() => {
    getAllSettings().then(s => {
      setSettings(s)
      setHost(s.proxy.host)
      setPort(s.proxy.port)
      setMode(s.proxy.mode)
    }).catch(() => {})
  }, [])

  const handleSave = async () => {
    setSaving(true); setMsg('')
    try {
      const r = await updateProxySettings({ host, port, mode })
      setHost(r.host); setPort(r.port); setMode(r.mode)
      setMsg('Proxy settings updated')
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || 'Failed to save')
    } finally { setSaving(false) }
  }

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Settings2 className="w-6 h-6 text-purple-400" />
        <h1 className="text-xl font-bold text-gray-100">Settings</h1>
      </div>

      {settings && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
          <div className="text-xs text-gray-500">System</div>
          <div className="grid grid-cols-2 gap-4">
            <div><span className="text-xs text-gray-500">API Host</span><p className="text-sm text-gray-200 font-mono">{settings.api_host}</p></div>
            <div><span className="text-xs text-gray-500">API Port</span><p className="text-sm text-gray-200 font-mono">{settings.api_port}</p></div>
          </div>
        </div>
      )}

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
        <h2 className="text-sm font-semibold text-gray-300">Proxy Settings</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs text-gray-500 mb-1">Listen Host</label>
            <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" value={host} onChange={e => setHost(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Port</label>
            <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" type="number" value={port} onChange={e => setPort(Number(e.target.value))} />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Mode</label>
            <select className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" value={mode} onChange={e => setMode(e.target.value)}>
              <option value="regular">Regular</option>
              <option value="transparent">Transparent</option>
              <option value="both">Both</option>
            </select>
          </div>
        </div>
        <button onClick={handleSave} disabled={saving} className="bg-purple-600 hover:bg-purple-700 disabled:opacity-40 px-4 py-2 rounded text-sm font-medium text-white flex items-center gap-2 transition-colors">
          <Save className="w-4 h-4" /> {saving ? 'Saving...' : 'Save'}
        </button>
        {msg && <p className="text-xs text-green-400">{msg}</p>}
      </div>
    </div>
  )
}

import { useState, useEffect } from 'react'
import { apiClient } from '../api/client'

interface Layer {
  url: string
  opacity: number
  position: { x: number; y: number }
  size: { width: number; height: number }
  label: string
  is_target: boolean
}

interface SavedConfig {
  id: string
  session_id: string
  name: string
  target_url: string
  created_at: string
  updated_at: string
  layers: Layer[]
  config: Record<string, any>
}

function emptyLayer(): Layer {
  return { url: '', opacity: 0.5, position: { x: 0, y: 0 }, size: { width: 300, height: 200 }, label: '', is_target: false }
}

export function Clickbandit() {
  const [targetUrl, setTargetUrl] = useState('')
  const [configName, setConfigName] = useState('')
  const [layers, setLayers] = useState<Layer[]>([emptyLayer()])
  const [configs, setConfigs] = useState<SavedConfig[]>([])
  const [generatedHtml, setGeneratedHtml] = useState('')
  const [error, setError] = useState('')
  const [editingId, setEditingId] = useState<string | null>(null)

  useEffect(() => {
    apiClient.get('/api/clickbandit/').then(({ data }) => setConfigs(data)).catch(() => {})
  }, [])

  const updateLayer = (idx: number, field: string, value: any) => {
    setLayers((prev) => {
      const next = [...prev]
      if (field.startsWith('position.')) {
        const key = field.split('.')[1]
        next[idx] = { ...next[idx], position: { ...next[idx].position, [key]: value } }
      } else if (field.startsWith('size.')) {
        const key = field.split('.')[1]
        next[idx] = { ...next[idx], size: { ...next[idx].size, [key]: value } }
      } else {
        next[idx] = { ...next[idx], [field]: value }
      }
      return next
    })
  }

  const addLayer = () => setLayers((prev) => [...prev, emptyLayer()])

  const removeLayer = (idx: number) => setLayers((prev) => prev.filter((_, i) => i !== idx))

  const saveConfig = async () => {
    if (!targetUrl || !configName) return
    setError('')
    try {
      if (editingId) {
        await apiClient.put(`/api/clickbandit/${editingId}`, { name: configName, target_url: targetUrl, layers, config: {} })
      } else {
        await apiClient.post('/api/clickbandit/', { session_id: '00000000-0000-0000-0000-000000000001', name: configName, target_url: targetUrl, layers, config: {} })
      }
      const { data } = await apiClient.get('/api/clickbandit/')
      setConfigs(data)
      setEditingId(null)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const loadConfig = (cfg: SavedConfig) => {
    setTargetUrl(cfg.target_url)
    setConfigName(cfg.name)
    setLayers(cfg.layers.length > 0 ? cfg.layers : [emptyLayer()])
    setEditingId(cfg.id)
  }

  const deleteConfig = async (id: string) => {
    await apiClient.delete(`/api/clickbandit/${id}`)
    setConfigs((prev) => prev.filter((c) => c.id !== id))
  }

  const generatePoc = async () => {
    setError('')
    setGeneratedHtml('')
    try {
      if (editingId) {
        const { data } = await apiClient.post(`/api/clickbandit/${editingId}/generate`)
        setGeneratedHtml(data.html)
      } else {
        const { data } = await apiClient.post('/api/clickbandit/generate', { target_url: targetUrl, layers, config: {} })
        setGeneratedHtml(data.html)
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const openInNewTab = () => {
    const blob = new Blob([generatedHtml], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    window.open(url, '_blank')
    setTimeout(() => URL.revokeObjectURL(url), 60000)
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300">
        Clickbandit — Clickjacking POC Builder
      </div>
      <div className="flex-1 flex overflow-hidden">
        <div className="w-1/2 p-3 space-y-3 overflow-auto border-r border-gray-800">
          {error && (
            <div className="bg-red-900/50 border border-red-800 rounded px-3 py-2 text-xs text-red-300">{error}</div>
          )}

          <div>
            <label className="text-xs text-gray-500 block mb-1">Target URL</label>
            <input
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono"
              placeholder="https://example.com"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
            />
          </div>

          <div>
            <label className="text-xs text-gray-500 block mb-1">Config Name</label>
            <input
              className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
              placeholder="My POC"
              value={configName}
              onChange={(e) => setConfigName(e.target.value)}
            />
          </div>

          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-500 font-medium">Layers ({layers.length})</span>
            <button
              className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium"
              onClick={addLayer}
            >
              Add Layer
            </button>
          </div>

          <div className="space-y-2">
            {layers.map((layer, idx) => (
              <div key={idx} className="bg-gray-900 border border-gray-700 rounded p-2 space-y-1.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400 font-medium">Layer {idx + 1}</span>
                  <button
                    className="text-red-400 hover:text-red-300"
                    onClick={() => removeLayer(idx)}
                  >
                    Remove
                  </button>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-gray-500 block">URL</label>
                    <input
                      className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200 font-mono"
                      value={layer.url}
                      onChange={(e) => updateLayer(idx, 'url', e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="text-gray-500 block">Label</label>
                    <input
                      className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200"
                      value={layer.label}
                      onChange={(e) => updateLayer(idx, 'label', e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="text-gray-500 block">Opacity ({layer.opacity.toFixed(2)})</label>
                    <input
                      type="range"
                      min="0"
                      max="1"
                      step="0.01"
                      className="w-full accent-purple-500"
                      value={layer.opacity}
                      onChange={(e) => updateLayer(idx, 'opacity', parseFloat(e.target.value))}
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <label className="flex items-center gap-1 text-gray-300">
                      <input
                        type="checkbox"
                        className="accent-purple-500"
                        checked={layer.is_target}
                        onChange={(e) => updateLayer(idx, 'is_target', e.target.checked)}
                      />
                      Is Target
                    </label>
                  </div>
                  <div>
                    <label className="text-gray-500 block">X</label>
                    <input
                      type="number"
                      className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200"
                      value={layer.position.x}
                      onChange={(e) => updateLayer(idx, 'position.x', parseInt(e.target.value) || 0)}
                    />
                  </div>
                  <div>
                    <label className="text-gray-500 block">Y</label>
                    <input
                      type="number"
                      className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200"
                      value={layer.position.y}
                      onChange={(e) => updateLayer(idx, 'position.y', parseInt(e.target.value) || 0)}
                    />
                  </div>
                  <div>
                    <label className="text-gray-500 block">Width</label>
                    <input
                      type="number"
                      className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200"
                      value={layer.size.width}
                      onChange={(e) => updateLayer(idx, 'size.width', parseInt(e.target.value) || 0)}
                    />
                  </div>
                  <div>
                    <label className="text-gray-500 block">Height</label>
                    <input
                      type="number"
                      className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200"
                      value={layer.size.height}
                      onChange={(e) => updateLayer(idx, 'size.height', parseInt(e.target.value) || 0)}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="flex gap-2 pt-2 border-t border-gray-800">
            <button
              className="bg-purple-600 hover:bg-purple-700 px-4 py-1.5 rounded text-xs font-medium disabled:opacity-50"
              onClick={saveConfig}
              disabled={!targetUrl || !configName}
            >
              {editingId ? 'Update Config' : 'Save Config'}
            </button>
            <button
              className="bg-gray-700 hover:bg-gray-600 px-4 py-1.5 rounded text-xs font-medium disabled:opacity-50"
              onClick={generatePoc}
              disabled={!targetUrl}
            >
              Generate POC
            </button>
            {generatedHtml && (
              <button
                className="bg-blue-700 hover:bg-blue-600 px-4 py-1.5 rounded text-xs font-medium"
                onClick={openInNewTab}
              >
                Open in Tab
              </button>
            )}
          </div>

          {generatedHtml && (
            <div>
              <label className="text-xs text-gray-500 block mb-1">Generated HTML</label>
              <textarea
                className="w-full h-40 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-[10px] text-gray-300 font-mono"
                value={generatedHtml}
                readOnly
              />
            </div>
          )}

          {configs.length > 0 && (
            <div className="border border-gray-800 rounded overflow-hidden">
              <div className="px-3 py-2 border-b border-gray-800 text-xs text-gray-400 font-medium">Saved Configs</div>
              <div className="divide-y divide-gray-800">
                {configs.map((cfg) => (
                  <div key={cfg.id} className="flex items-center justify-between px-3 py-2 text-xs">
                    <div>
                      <span className="text-gray-200">{cfg.name}</span>
                      <span className="text-gray-500 ml-2 font-mono">{cfg.target_url}</span>
                    </div>
                    <div className="flex gap-2">
                      <button
                        className="text-purple-400 hover:text-purple-300"
                        onClick={() => loadConfig(cfg)}
                      >
                        Load
                      </button>
                      <button
                        className="text-red-400 hover:text-red-300"
                        onClick={() => deleteConfig(cfg.id)}
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="w-1/2 p-3 overflow-auto">
          <div className="text-xs text-gray-500 mb-2">Canvas Preview</div>
          <div className="relative bg-gray-900 border border-gray-700 rounded min-h-[400px]" style={{ minHeight: '400px' }}>
            {layers.map((layer, idx) => (
              <div
                key={idx}
                className="absolute border-2 rounded flex items-center justify-center text-[10px] font-mono overflow-hidden"
                style={{
                  left: layer.position.x,
                  top: layer.position.y,
                  width: layer.size.width || 100,
                  height: layer.size.height || 60,
                  opacity: layer.opacity,
                  zIndex: idx + 1,
                  borderColor: layer.is_target ? '#e94560' : '#555',
                  backgroundColor: layer.is_target ? 'rgba(233,69,96,0.15)' : 'rgba(15,52,96,0.3)',
                }}
              >
                <div
                  className="absolute"
                  style={{
                    top: -16,
                    left: 4,
                    fontSize: 9,
                    color: layer.is_target ? '#e94560' : '#888',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {layer.label || `Layer ${idx + 1}`}
                  {layer.is_target ? ' [TARGET]' : ''}
                </div>
              </div>
            ))}
            {layers.length === 0 && (
              <div className="text-gray-600 text-xs flex items-center justify-center h-full min-h-[400px]">
                No layers added
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

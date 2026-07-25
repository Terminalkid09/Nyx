import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Play, Save, ChevronDown, ChevronRight, Plus, X } from 'lucide-react'
import { apiClient } from '../api/client'

interface Template {
  id: string
  name: string
  config: Record<string, any>
}

interface FormField {
  name: string
  value: string
}

export function PipelineConfig() {
  const navigate = useNavigate()
  const [templates, setTemplates] = useState<Template[]>([])
  const [selectedTemplate, setSelectedTemplate] = useState('')
  const [targetUrl, setTargetUrl] = useState('')
  const [error, setError] = useState('')
  const [starting, setStarting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [templateName, setTemplateName] = useState('')

  const [sections, setSections] = useState({
    crawl: true,
    discovery: false,
    fuzz: false,
    active_scan: false,
  })

  const [crawlConfig, setCrawlConfig] = useState({
    max_depth: 3,
    max_pages: 100,
    respect_robots_txt: true,
    form_fill: [{ name: '', value: '' }] as FormField[],
  })

  const [discoveryConfig, setDiscoveryConfig] = useState({
    enable: true,
    wordlist_path: '',
  })

  const [fuzzConfig, setFuzzConfig] = useState({
    enable: false,
    attack_type: 'sniper',
  })

  const [activeScanConfig, setActiveScanConfig] = useState({
    enable: false,
  })

  const [wordlistPaths, setWordlistPaths] = useState<string[]>([])

  useEffect(() => {
    Promise.all([
      apiClient.get('/api/automations/templates').catch(() => ({ data: [] })),
      apiClient.get('/api/content-discovery/wordlists').catch(() => ({ data: [] })),
    ])
      .then(([templatesRes, wordlistsRes]) => {
        setTemplates(templatesRes.data)
        setWordlistPaths(wordlistsRes.data)
      })
      .catch((err: any) => setError(err.response?.data?.detail || err.message))
  }, [])

  const handleTemplateSelect = (templateId: string) => {
    setSelectedTemplate(templateId)
    if (!templateId) return
    const tmpl = templates.find((t) => t.id === templateId)
    if (!tmpl) return

    const cfg = tmpl.config
    setTargetUrl(cfg.target_url || '')
    if (cfg.crawl) {
      setCrawlConfig({
        max_depth: cfg.crawl.max_depth ?? 3,
        max_pages: cfg.crawl.max_pages ?? 100,
        respect_robots_txt: cfg.crawl.respect_robots_txt ?? true,
        form_fill: cfg.crawl.form_fill?.length > 0 ? cfg.crawl.form_fill : [{ name: '', value: '' }],
      })
    }
    if (cfg.discovery) {
      setDiscoveryConfig({
        enable: cfg.discovery.enable ?? true,
        wordlist_path: cfg.discovery.wordlist_path || '',
      })
    }
    if (cfg.fuzz) {
      setFuzzConfig({
        enable: cfg.fuzz.enable ?? false,
        attack_type: cfg.fuzz.attack_type || 'sniper',
      })
    }
    if (cfg.active_scan) {
      setActiveScanConfig({
        enable: cfg.active_scan.enable ?? false,
      })
    }
  }

  const addFormField = () => {
    setCrawlConfig((prev) => ({
      ...prev,
      form_fill: [...prev.form_fill, { name: '', value: '' }],
    }))
  }

  const removeFormField = (idx: number) => {
    setCrawlConfig((prev) => ({
      ...prev,
      form_fill: prev.form_fill.filter((_, i) => i !== idx),
    }))
  }

  const updateFormField = (idx: number, field: Partial<FormField>) => {
    setCrawlConfig((prev) => ({
      ...prev,
      form_fill: prev.form_fill.map((f, i) => (i === idx ? { ...f, ...field } : f)),
    }))
  }

  const buildConfig = () => ({
    target_url: targetUrl,
    crawl: {
      max_depth: crawlConfig.max_depth,
      max_pages: crawlConfig.max_pages,
      respect_robots_txt: crawlConfig.respect_robots_txt,
      form_fill: crawlConfig.form_fill.filter((f) => f.name && f.value),
    },
    discovery: {
      enable: discoveryConfig.enable,
      wordlist_path: discoveryConfig.wordlist_path || undefined,
    },
    fuzz: {
      enable: fuzzConfig.enable,
      attack_type: fuzzConfig.attack_type,
    },
    active_scan: {
      enable: activeScanConfig.enable,
    },
  })

  const handleStartScan = async () => {
    if (!targetUrl) {
      setError('Target URL is required')
      return
    }
    setError('')
    setStarting(true)
    try {
      const config = buildConfig()
      await apiClient.post('/api/pipeline/start', config)
      navigate('/dashboard')
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setStarting(false)
    }
  }

  const handleSaveTemplate = async () => {
    if (!templateName.trim()) {
      setError('Template name is required')
      return
    }
    setError('')
    setSaving(true)
    try {
      await apiClient.post('/api/automations/templates', {
        name: templateName,
        config: buildConfig(),
      })
      setTemplateName('')
      const { data } = await apiClient.get('/api/automations/templates')
      setTemplates(data)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <Play size={16} className="text-purple-500" />
        <span>New Full Scan Pipeline</span>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>}

        {/* Target URL */}
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <label className="text-xs font-medium text-gray-400 block mb-2">Target URL</label>
          <input
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://target.example.com"
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs font-mono text-gray-200 placeholder-gray-500"
          />
        </div>

        {/* Template Selector */}
        <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
          <label className="text-xs font-medium text-gray-400 block mb-2">Load Template</label>
          <select
            value={selectedTemplate}
            onChange={(e) => handleTemplateSelect(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-200"
          >
            <option value="">Select a template...</option>
            {templates.map((t) => (
              <option key={t.id} value={t.id}>{t.name}</option>
            ))}
          </select>
          {templates.length === 0 && (
            <div className="text-[10px] text-gray-500 mt-1">No templates saved yet.</div>
          )}
        </div>

        {/* Crawl Config */}
        <div className="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
          <button
            onClick={() => setSections((s) => ({ ...s, crawl: !s.crawl }))}
            className="w-full flex items-center gap-2 p-3 text-xs font-medium text-gray-300 hover:bg-gray-800 transition-colors"
          >
            {sections.crawl ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            Crawl Config
          </button>
          {sections.crawl && (
            <div className="p-3 pt-0 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-gray-500 block mb-1">Max Depth (1-5)</label>
                  <input
                    type="range"
                    min={1}
                    max={5}
                    value={crawlConfig.max_depth}
                    onChange={(e) => setCrawlConfig((c) => ({ ...c, max_depth: parseInt(e.target.value) }))}
                    className="w-full accent-purple-500"
                  />
                  <span className="text-xs text-gray-400">{crawlConfig.max_depth}</span>
                </div>
                <div>
                  <label className="text-[10px] text-gray-500 block mb-1">Max Pages</label>
                  <input
                    type="number"
                    min={1}
                    value={crawlConfig.max_pages}
                    onChange={(e) => setCrawlConfig((c) => ({ ...c, max_pages: parseInt(e.target.value) || 1 }))}
                    className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                  />
                </div>
              </div>
              <label className="flex items-center gap-2 text-xs text-gray-400">
                <input
                  type="checkbox"
                  checked={crawlConfig.respect_robots_txt}
                  onChange={(e) => setCrawlConfig((c) => ({ ...c, respect_robots_txt: e.target.checked }))}
                  className="accent-purple-500"
                />
                Respect robots.txt
              </label>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-[10px] text-gray-500">Form Fill Fields</label>
                  <button
                    onClick={addFormField}
                    className="text-[10px] text-purple-400 hover:text-purple-300 flex items-center gap-1"
                  >
                    <Plus size={10} /> Add Field
                  </button>
                </div>
                {crawlConfig.form_fill.map((field, i) => (
                  <div key={i} className="flex items-center gap-2 mb-1">
                    <input
                      value={field.name}
                      onChange={(e) => updateFormField(i, { name: e.target.value })}
                      placeholder="field name"
                      className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-200 placeholder-gray-500"
                    />
                    <input
                      value={field.value}
                      onChange={(e) => updateFormField(i, { value: e.target.value })}
                      placeholder="value"
                      className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-200 placeholder-gray-500"
                    />
                    <button
                      onClick={() => removeFormField(i)}
                      className="p-1 text-red-400 hover:text-red-300"
                    >
                      <X size={12} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Discovery Config */}
        <div className="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
          <button
            onClick={() => setSections((s) => ({ ...s, discovery: !s.discovery }))}
            className="w-full flex items-center gap-2 p-3 text-xs font-medium text-gray-300 hover:bg-gray-800 transition-colors"
          >
            {sections.discovery ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            <label className="flex items-center gap-2 cursor-pointer" onClick={(e) => e.stopPropagation()}>
              <input
                type="checkbox"
                checked={discoveryConfig.enable}
                onChange={(e) => setDiscoveryConfig((c) => ({ ...c, enable: e.target.checked }))}
                className="accent-purple-500"
                onClick={(e) => e.stopPropagation()}
              />
              Discovery Config
            </label>
          </button>
          {sections.discovery && (
            <div className="p-3 pt-0 space-y-3">
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">Wordlist Path</label>
                <select
                  value={discoveryConfig.wordlist_path}
                  onChange={(e) => setDiscoveryConfig((c) => ({ ...c, wordlist_path: e.target.value }))}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                >
                  <option value="">Default</option>
                  {wordlistPaths.map((wp) => (
                    <option key={wp} value={wp}>{wp}</option>
                  ))}
                </select>
              </div>
            </div>
          )}
        </div>

        {/* Fuzz Config */}
        <div className="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
          <button
            onClick={() => setSections((s) => ({ ...s, fuzz: !s.fuzz }))}
            className="w-full flex items-center gap-2 p-3 text-xs font-medium text-gray-300 hover:bg-gray-800 transition-colors"
          >
            {sections.fuzz ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            <label className="flex items-center gap-2 cursor-pointer" onClick={(e) => e.stopPropagation()}>
              <input
                type="checkbox"
                checked={fuzzConfig.enable}
                onChange={(e) => setFuzzConfig((c) => ({ ...c, enable: e.target.checked }))}
                className="accent-purple-500"
                onClick={(e) => e.stopPropagation()}
              />
              Fuzz Config
            </label>
          </button>
          {sections.fuzz && (
            <div className="p-3 pt-0">
              <div>
                <label className="text-[10px] text-gray-500 block mb-1">Attack Type</label>
                <select
                  value={fuzzConfig.attack_type}
                  onChange={(e) => setFuzzConfig((c) => ({ ...c, attack_type: e.target.value }))}
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                >
                  <option value="sniper">Sniper</option>
                  <option value="batteringram">Battering Ram</option>
                  <option value="pitchfork">Pitchfork</option>
                  <option value="clusterbomb">Cluster Bomb</option>
                </select>
              </div>
            </div>
          )}
        </div>

        {/* Active Scan Config */}
        <div className="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
          <button
            onClick={() => setSections((s) => ({ ...s, active_scan: !s.active_scan }))}
            className="w-full flex items-center gap-2 p-3 text-xs font-medium text-gray-300 hover:bg-gray-800 transition-colors"
          >
            {sections.active_scan ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            <label className="flex items-center gap-2 cursor-pointer" onClick={(e) => e.stopPropagation()}>
              <input
                type="checkbox"
                checked={activeScanConfig.enable}
                onChange={(e) => setActiveScanConfig((c) => ({ ...c, enable: e.target.checked }))}
                className="accent-purple-500"
                onClick={(e) => e.stopPropagation()}
              />
              Active Scan Config
            </label>
          </button>
          {sections.active_scan && (
            <div className="p-3 pt-0">
              <div className="text-xs text-gray-500">
                Active scanning checks for vulnerabilities by sending crafted payloads.
              </div>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleStartScan}
            disabled={starting || !targetUrl}
            className="flex items-center gap-2 bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded text-xs font-medium disabled:opacity-50 transition-colors"
          >
            <Play size={14} />
            {starting ? 'Starting...' : 'Start Scan'}
          </button>
          <div className="flex items-center gap-2 flex-1">
            <input
              value={templateName}
              onChange={(e) => setTemplateName(e.target.value)}
              placeholder="Template name"
              className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-200 placeholder-gray-500"
            />
            <button
              onClick={handleSaveTemplate}
              disabled={saving || !templateName.trim()}
              className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded text-xs font-medium disabled:opacity-50 transition-colors"
            >
              <Save size={14} />
              {saving ? 'Saving...' : 'Save as Template'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

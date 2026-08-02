import { useState, useEffect } from 'react'
import { Activity, Webhook as WebhookIcon, Clock, FileText, Plus, Trash2, ToggleLeft, ToggleRight, Play, Copy, Check } from 'lucide-react'
import { listWebhooks, createWebhook, deleteWebhook, testWebhook, listSchedules, createSchedule, deleteSchedule, toggleSchedule, listTemplates, deleteTemplate, listReports, generateCSRF, Webhook, Schedule, Template, Report } from '../../api/endpoints/automations'

type Tab = 'webhooks' | 'schedules' | 'templates' | 'csrf'

export function Automations() {
  const [tab, setTab] = useState<Tab>('webhooks')
  const [webhooks, setWebhooks] = useState<Webhook[]>([])
  const [schedules, setSchedules] = useState<Schedule[]>([])
  const [templates, setTemplates] = useState<Template[]>([])
  const [reports, setReports] = useState<Report[]>([])
  const [showWHForm, setShowWHForm] = useState(false)
  const [showSchedForm, setShowSchedForm] = useState(false)
  const [whName, setWHName] = useState('')
  const [whUrl, setWHUrl] = useState('')
  const [whType, setWHType] = useState('slack')
  const [schedName, setSchedName] = useState('')
  const [schedTarget, setSchedTarget] = useState('')
  const [schedCron, setSchedCron] = useState('0 */6 * * *')
  const [csrfUrl, setCsrfUrl] = useState('')
  const [csrfHtml, setCsrfHtml] = useState('')
  const [copied, setCopied] = useState(false)

  const fetchAll = async () => {
    try { setWebhooks(await listWebhooks()) } catch {}
    try { setSchedules(await listSchedules()) } catch {}
    try { setTemplates(await listTemplates()) } catch {}
    try { setReports(await listReports()) } catch {}
  }
  useEffect(() => { fetchAll() }, [])

  const handleCreateWH = async () => {
    if (!whName || !whUrl) return
    await createWebhook({ name: whName, type: whType, url: whUrl, events: ['finding.created'] })
    setShowWHForm(false); setWHName(''); setWHUrl('')
    const r = await listWebhooks(); setWebhooks(r)
  }

  const handleCreateSched = async () => {
    if (!schedName || !schedTarget) return
    await createSchedule({ name: schedName, target_url: schedTarget, cron: schedCron })
    setShowSchedForm(false); setSchedName(''); setSchedTarget(''); setSchedCron('0 */6 * * *')
    const r = await listSchedules(); setSchedules(r)
  }

  const handleCSRF = async () => {
    if (!csrfUrl) return
    const r = await generateCSRF(csrfUrl)
    setCsrfHtml(r.html)
  }

  const handleCopy = async () => {
    await navigator.clipboard.writeText(csrfHtml)
    setCopied(true); setTimeout(() => setCopied(false), 2000)
  }

  const tabs: { key: Tab; label: string; icon: any }[] = [
    { key: 'webhooks', label: 'Webhooks', icon: WebhookIcon },
    { key: 'schedules', label: 'Schedules', icon: Clock },
    { key: 'templates', label: 'Templates', icon: FileText },
    { key: 'csrf', label: 'CSRF PoC', icon: Play },
  ]

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Activity className="w-6 h-6 text-purple-400" />
        <h1 className="text-xl font-bold text-gray-100">Automations</h1>
      </div>

      <div className="flex gap-1 border-b border-gray-800">
        {tabs.map(({ key, label, icon: Icon }) => (
          <button key={key} onClick={() => setTab(key)} className={`px-4 py-2 text-xs font-medium border-b-2 transition-colors ${tab === key ? 'border-purple-500 text-purple-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>
            <Icon className="w-3.5 h-3.5 inline mr-1.5" />{label}
          </button>
        ))}
      </div>

      {tab === 'webhooks' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button onClick={() => setShowWHForm(!showWHForm)} className="bg-purple-600 hover:bg-purple-700 px-3 py-1.5 rounded text-xs font-medium text-white flex items-center gap-1.5 transition-colors"><Plus className="w-3.5 h-3.5" /> Add Webhook</button>
          </div>
          {showWHForm && (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <input className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" value={whName} onChange={e => setWHName(e.target.value)} placeholder="Name" />
                <input className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" value={whUrl} onChange={e => setWHUrl(e.target.value)} placeholder="Webhook URL" />
                <select className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" value={whType} onChange={e => setWHType(e.target.value)}>
                  <option value="slack">Slack</option>
                  <option value="discord">Discord</option>
                  <option value="teams">Teams</option>
                  <option value="generic">Generic</option>
                </select>
              </div>
              <button onClick={handleCreateWH} className="bg-purple-600 hover:bg-purple-700 px-4 py-1.5 rounded text-xs font-medium text-white transition-colors">Create</button>
            </div>
          )}
          {webhooks.map(w => (
            <div key={w.id} className="bg-gray-900 border border-gray-800 rounded-lg px-5 py-3 flex items-center justify-between">
              <div>
                <span className="text-sm font-medium text-gray-200">{w.name}</span>
                <span className="ml-2 text-[10px] text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">{w.type}</span>
                <p className="text-xs text-gray-500 mt-0.5">{w.url}</p>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => testWebhook(w.id)} className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors" title="Test"><Play className="w-3.5 h-3.5" /></button>
                <button onClick={() => deleteWebhook(w.id).then(fetchAll)} className="p-1.5 rounded hover:bg-gray-800 text-gray-500 hover:text-red-400 transition-colors"><Trash2 className="w-4 h-4" /></button>
              </div>
            </div>
          ))}
          {webhooks.length === 0 && <p className="text-center py-8 text-gray-500 text-sm">No webhooks configured.</p>}
        </div>
      )}

      {tab === 'schedules' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button onClick={() => setShowSchedForm(!showSchedForm)} className="bg-purple-600 hover:bg-purple-700 px-3 py-1.5 rounded text-xs font-medium text-white flex items-center gap-1.5"><Plus className="w-3.5 h-3.5" /> Schedule</button>
          </div>
          {showSchedForm && (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <input className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" value={schedName} onChange={e => setSchedName(e.target.value)} placeholder="Name" />
                <input className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" value={schedTarget} onChange={e => setSchedTarget(e.target.value)} placeholder="Target URL" />
                <input className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono" value={schedCron} onChange={e => setSchedCron(e.target.value)} placeholder="Cron: 0 */6 * * *" />
              </div>
              <button onClick={handleCreateSched} className="bg-purple-600 hover:bg-purple-700 px-4 py-1.5 rounded text-xs font-medium text-white transition-colors">Create</button>
            </div>
          )}
          {schedules.map(s => (
            <div key={s.id} className="bg-gray-900 border border-gray-800 rounded-lg px-5 py-3 flex items-center justify-between">
              <div>
                <span className="text-sm font-medium text-gray-200">{s.name}</span>
                <span className="ml-2 text-xs text-gray-500 font-mono">{s.cron}</span>
                <p className="text-xs text-gray-500 mt-0.5">{s.target_url}</p>
              </div>
              <button onClick={() => toggleSchedule(s.id).then(fetchAll)} className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors">
                {s.enabled ? <ToggleRight className="w-4 h-4 text-green-400" /> : <ToggleLeft className="w-4 h-4 text-gray-500" />}
              </button>
            </div>
          ))}
          {schedules.length === 0 && <p className="text-center py-8 text-gray-500 text-sm">No schedules configured.</p>}
        </div>
      )}

      {tab === 'templates' && (
        <div className="space-y-4">
          {templates.map(t => (
            <div key={t.id} className="bg-gray-900 border border-gray-800 rounded-lg px-5 py-3 flex items-center justify-between">
              <div>
                <span className="text-sm font-medium text-gray-200">{t.name}</span>
                <p className="text-xs text-gray-500 mt-0.5">{t.description}</p>
              </div>
              <button onClick={() => deleteTemplate(t.id).then(fetchAll)} className="p-1.5 rounded hover:bg-gray-800 text-gray-500 hover:text-red-400 transition-colors"><Trash2 className="w-4 h-4" /></button>
            </div>
          ))}
          {templates.length === 0 && <p className="text-center py-8 text-gray-500 text-sm">No templates available.</p>}
        </div>
      )}

      {tab === 'csrf' && (
        <div className="space-y-4">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4">
            <div className="flex items-end gap-3">
              <div className="flex-1">
                <label className="block text-xs text-gray-500 mb-1">Target URL</label>
                <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" value={csrfUrl} onChange={e => setCsrfUrl(e.target.value)} placeholder="https://example.com/api/action" />
              </div>
              <button onClick={handleCSRF} className="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded text-sm font-medium text-white flex items-center gap-2 transition-colors"><Play className="w-4 h-4" /> Generate PoC</button>
            </div>
          </div>
          {csrfHtml && (
            <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
              <div className="flex items-center justify-between px-5 py-3 border-b border-gray-800">
                <span className="text-sm font-semibold text-gray-300">CSRF PoC HTML</span>
                <button onClick={handleCopy} className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors">
                  {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
              <pre className="p-5 text-sm text-gray-300 font-mono overflow-x-auto whitespace-pre-wrap max-h-96 bg-gray-950/50">{csrfHtml}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

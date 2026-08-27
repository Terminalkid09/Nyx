import { useState, useEffect } from 'react'
import { Shield, FileCheck, AlertTriangle, CheckCircle, ChevronDown, ChevronRight, Download } from 'lucide-react'
import {
  getOwaspReport,
  getPciDssReport,
  getGdprReport,
  type OwaspReport,
  type PciDssReport,
  type GdprReport,
} from '../../api/endpoints/compliance'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10',
  high: 'text-orange-400 bg-orange-400/10',
  medium: 'text-yellow-400 bg-yellow-400/10',
  low: 'text-green-400 bg-green-400/10',
  info: 'text-gray-400 bg-gray-400/10',
}

function Badge({ pass, count }: { pass: boolean; count: number }) {
  if (pass) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-400/10 text-green-400">
        <CheckCircle size={12} /> PASS
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-400/10 text-red-400">
      <AlertTriangle size={12} /> {count} violation{count !== 1 ? 's' : ''}
    </span>
  )
}

function OwaspSection({ report }: { report: OwaspReport }) {
  const [expanded, setExpanded] = useState<string | null>(null)

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3 mb-4">
        <Shield size={20} className="text-purple-400" />
        <h3 className="text-sm font-semibold text-gray-200">OWASP Top 10 2021</h3>
        <span className="text-xs text-gray-500">
          {report.summary.categories_clean}/10 categories clean
        </span>
      </div>

      <div className="grid grid-cols-1 gap-1">
        {report.categories.map((cat) => (
          <div
            key={cat.id}
            className={`border rounded-lg transition-colors ${
              cat.pass
                ? 'border-green-900/30 bg-green-950/10'
                : 'border-red-900/30 bg-red-950/10'
            }`}
          >
            <button
              onClick={() => setExpanded(expanded === cat.id ? null : cat.id)}
              className="w-full flex items-center gap-3 px-3 py-2 text-left"
            >
              {expanded === cat.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              <span className="text-xs font-mono text-gray-400 w-20">{cat.id}</span>
              <span className="text-xs text-gray-300 flex-1">{cat.title}</span>
              <Badge pass={cat.pass} count={cat.finding_count} />
            </button>
            {expanded === cat.id && cat.findings.length > 0 && (
              <div className="px-6 pb-2 space-y-1">
                {cat.findings.map((f) => (
                  <div key={f.id} className="flex items-center gap-2 text-xs">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${SEVERITY_COLORS[f.severity] || ''}`}>
                      {f.severity.toUpperCase()}
                    </span>
                    <span className="text-gray-300 truncate">{f.title}</span>
                    {f.cwe && <span className="text-gray-500 font-mono">{f.cwe}</span>}
                    <span className="text-gray-600 ml-auto">{f.host}{f.path}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function PciDssSection({ report }: { report: PciDssReport }) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 mb-4">
        <FileCheck size={20} className="text-blue-400" />
        <h3 className="text-sm font-semibold text-gray-200">PCI-DSS v4.0</h3>
        <span className="text-xs text-gray-500">
          {report.summary.passed}/{report.summary.total_requirements} passed
        </span>
      </div>

      <div className="grid grid-cols-1 gap-1">
        {report.requirements.map((req) => (
          <div
            key={req.requirement_id}
            className={`flex items-center gap-3 px-3 py-2 border rounded-lg ${
              req.status === 'PASS'
                ? 'border-green-900/30 bg-green-950/10'
                : 'border-red-900/30 bg-red-950/10'
            }`}
          >
            <span className="text-xs font-mono text-gray-400 w-16">{req.requirement_id}</span>
            <span className="text-xs text-gray-300 flex-1">{req.title}</span>
            <Badge pass={req.status === 'PASS'} count={req.violation_count} />
          </div>
        ))}
      </div>
    </div>
  )
}

function GdprSection({ report }: { report: GdprReport }) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 mb-4">
        <Shield size={20} className="text-cyan-400" />
        <h3 className="text-sm font-semibold text-gray-200">GDPR Art. 32 — Security of Processing</h3>
        <span className="text-xs text-gray-500">
          {report.summary.passed}/{report.summary.total_articles} passed
        </span>
      </div>

      <div className="grid grid-cols-1 gap-1">
        {report.articles.map((art) => (
          <div
            key={art.article}
            className={`flex items-center gap-3 px-3 py-2 border rounded-lg ${
              art.status === 'PASS'
                ? 'border-green-900/30 bg-green-950/10'
                : 'border-red-900/30 bg-red-950/10'
            }`}
          >
            <span className="text-xs font-mono text-gray-400 w-16">{art.article}</span>
            <span className="text-xs text-gray-300 flex-1">{art.title}</span>
            <Badge pass={art.status === 'PASS'} count={art.violation_count} />
          </div>
        ))}
      </div>
    </div>
  )
}

export function Compliance() {
  const [tab, setTab] = useState<'owasp' | 'pci' | 'gdpr'>('owasp')
  const [owasp, setOwasp] = useState<OwaspReport | null>(null)
  const [pci, setPci] = useState<PciDssReport | null>(null)
  const [gdpr, setGdpr] = useState<GdprReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const [o, p, g] = await Promise.all([getOwaspReport(), getPciDssReport(), getGdprReport()])
      setOwasp(o)
      setPci(p)
      setGdpr(g)
    } catch (e: any) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const exportJson = () => {
    const data = { owasp, pci_dss: pci, gdpr }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `nyx-compliance-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const tabs = [
    { id: 'owasp' as const, label: 'OWASP Top 10', icon: Shield },
    { id: 'pci' as const, label: 'PCI-DSS', icon: FileCheck },
    { id: 'gdpr' as const, label: 'GDPR', icon: Shield },
  ]

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-medium text-gray-300">
          <FileCheck size={16} />
          <span>Compliance Reports</span>
          {owasp && (
            <span className={`text-xs px-2 py-0.5 rounded-full ${
              owasp.summary.categories_with_findings > 0
                ? 'bg-red-400/10 text-red-400'
                : 'bg-green-400/10 text-green-400'
            }`}>
              {owasp.summary.total_findings} finding{owasp.summary.total_findings !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        <button
          onClick={exportJson}
          disabled={!owasp}
          className="flex items-center gap-1 px-2 py-1 text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-800 rounded transition-colors disabled:opacity-50"
        >
          <Download size={12} /> Export JSON
        </button>
      </div>

      <div className="flex border-b border-gray-800">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-1 px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
              tab === t.id
                ? 'border-purple-500 text-purple-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <t.icon size={14} />
            {t.label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-auto p-4">
        {loading && (
          <div className="flex items-center justify-center h-full text-gray-500 text-sm">
            Generating compliance reports…
          </div>
        )}
        {error && (
          <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>
        )}
        {!loading && !error && owasp && tab === 'owasp' && <OwaspSection report={owasp} />}
        {!loading && !error && pci && tab === 'pci' && <PciDssSection report={pci} />}
        {!loading && !error && gdpr && tab === 'gdpr' && <GdprSection report={gdpr} />}
      </div>
    </div>
  )
}
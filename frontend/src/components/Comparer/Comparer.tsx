import { useState, useEffect } from 'react'
import { GitCompare, Plus, Trash2 } from 'lucide-react'
import {
  fetchComparerItems,
  createComparerItem,
  deleteComparerItem,
  compareItem,
} from '../../api/endpoints/comparer'
import { ComparerItem, DiffResult } from '../../types'
import { useProxyStore } from '../../store/useProxyStore'

interface DiffLine {
  type: 'added' | 'removed' | 'unchanged'
  leftLine: string | null
  rightLine: string | null
}

function computeDiff(result: DiffResult): DiffLine[] {
  const lines: DiffLine[] = []
  const sections = result.sections
  if (sections && sections.length > 0) {
    for (const section of sections) {
      const type = section.type === 'added' ? 'added' : section.type === 'removed' ? 'removed' : 'unchanged'
      for (const line of section.lines) {
        lines.push({
          type,
          leftLine: type === 'added' ? null : line,
          rightLine: type === 'removed' ? null : line,
        })
      }
    }
  } else {
    const maxLen = Math.max(result.added.length, result.removed.length, result.unchanged.length)
    for (let i = 0; i < maxLen; i++) {
      const u = result.unchanged[i]
      const r = result.removed[i]
      const a = result.added[i]
      if (u != null) lines.push({ type: 'unchanged', leftLine: u, rightLine: u })
      if (r != null) lines.push({ type: 'removed', leftLine: r, rightLine: null })
      if (a != null) lines.push({ type: 'added', leftLine: null, rightLine: a })
    }
  }
  return lines
}

export function Comparer() {
  const requests = useProxyStore((s) => s.requests)
  const [leftContent, setLeftContent] = useState('')
  const [rightContent, setRightContent] = useState('')
  const [leftLabel, setLeftLabel] = useState('Left')
  const [rightLabel, setRightLabel] = useState('Right')
  const [leftReqId, setLeftReqId] = useState('')
  const [rightReqId, setRightReqId] = useState('')
  const [items, setItems] = useState<ComparerItem[]>([])
  const [diffResult, setDiffResult] = useState<DiffResult | null>(null)
  const [diffLines, setDiffLines] = useState<DiffLine[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchComparerItems().then(setItems).catch(() => {})
  }, [])

  const loadRequestContent = (reqId: string, side: 'left' | 'right') => {
    const req = requests.find((r) => r.id === reqId)
    if (!req) return
    const headers = Object.entries(req.request_headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\r\n')
    const content = `${req.method} ${req.path} HTTP/${req.http_version || '1.1'}\r\n${headers}\r\n\r\n${req.request_body || ''}`
    if (side === 'left') setLeftContent(content)
    else setRightContent(content)
  }

  useEffect(() => {
    if (leftReqId) loadRequestContent(leftReqId, 'left')
  }, [leftReqId])

  useEffect(() => {
    if (rightReqId) loadRequestContent(rightReqId, 'right')
  }, [rightReqId])

  const handleSaveAndCompare = async () => {
    if (!leftContent && !rightContent) return
    setLoading(true)
    setError('')
    setDiffResult(null)
    try {
      const item = await createComparerItem({
        left_content: leftContent || undefined,
        right_content: rightContent || undefined,
        left_label: leftLabel,
        right_label: rightLabel,
        left_request_id: leftReqId || undefined,
        right_request_id: rightReqId || undefined,
      })
      setItems((prev) => [...prev, item])
      const result = await compareItem(item.id)
      setDiffResult(result)
      setDiffLines(computeDiff(result))
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleCompareSaved = async (item: ComparerItem) => {
    setLoading(true)
    setError('')
    setDiffResult(null)
    if (item.left_content) setLeftContent(item.left_content)
    if (item.right_content) setRightContent(item.right_content)
    if (item.left_label) setLeftLabel(item.left_label)
    if (item.right_label) setRightLabel(item.right_label)
    try {
      const result = await compareItem(item.id)
      setDiffResult(result)
      setDiffLines(computeDiff(result))
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (id: string) => {
    try {
      await deleteComparerItem(id)
      setItems((prev) => prev.filter((i) => i.id !== id))
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <GitCompare size={16} />
        <span>Comparer</span>
      </div>
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>}

        <div>
          <div className="text-xs font-medium text-gray-400 mb-1">Send to Comparer from Proxy</div>
          <div className="flex gap-2 items-center mb-2">
            <select
              className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
              value={leftReqId}
              onChange={(e) => setLeftReqId(e.target.value)}
            >
              <option value="">Left request...</option>
              {requests.slice(0, 100).map((r) => (
                <option key={r.id} value={r.id}>{r.method} {r.path}</option>
              ))}
            </select>
            <span className="text-gray-500 text-xs">vs</span>
            <select
              className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
              value={rightReqId}
              onChange={(e) => setRightReqId(e.target.value)}
            >
              <option value="">Right request...</option>
              {requests.slice(0, 100).map((r) => (
                <option key={r.id} value={r.id}>{r.method} {r.path}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <input
                className="bg-gray-800 border border-gray-700 rounded px-2 py-0.5 text-xs text-gray-200 w-32"
                value={leftLabel}
                onChange={(e) => setLeftLabel(e.target.value)}
              />
            </div>
            <textarea
              className="w-full h-48 bg-gray-900 border border-gray-800 rounded p-2 text-xs font-mono text-gray-300 resize-none"
              value={leftContent}
              onChange={(e) => setLeftContent(e.target.value)}
            />
          </div>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <input
                className="bg-gray-800 border border-gray-700 rounded px-2 py-0.5 text-xs text-gray-200 w-32"
                value={rightLabel}
                onChange={(e) => setRightLabel(e.target.value)}
              />
            </div>
            <textarea
              className="w-full h-48 bg-gray-900 border border-gray-800 rounded p-2 text-xs font-mono text-gray-300 resize-none"
              value={rightContent}
              onChange={(e) => setRightContent(e.target.value)}
            />
          </div>
        </div>

        <button
          onClick={handleSaveAndCompare}
          className="bg-purple-600 hover:bg-purple-700 px-4 py-1 rounded text-xs font-medium flex items-center gap-1 disabled:opacity-50"
          disabled={loading || (!leftContent && !rightContent)}
        >
          <GitCompare size={14} /> {loading ? 'Comparing...' : 'Compare'}
        </button>

        {diffResult && (
          <div className="bg-gray-900 border border-gray-800 rounded overflow-hidden">
            <div className="text-xs font-medium text-gray-400 p-2 border-b border-gray-800">
              Diff ({diffLines.length} lines)
            </div>
            <div className="overflow-auto max-h-80">
              <table className="w-full text-xs font-mono">
                <tbody>
                  {diffLines.map((line, i) => (
                    <tr
                      key={i}
                      className={
                        line.type === 'added' ? 'bg-green-900/30' :
                        line.type === 'removed' ? 'bg-red-900/30' :
                        'bg-transparent'
                      }
                    >
                      <td className="w-8 text-right text-gray-600 px-1 select-none">{i + 1}</td>
                      <td className={`w-8 text-center px-1 ${
                        line.type === 'added' ? 'text-green-400' :
                        line.type === 'removed' ? 'text-red-400' :
                        'text-gray-600'
                      }`}>
                        {line.type === 'added' ? '+' : line.type === 'removed' ? '-' : ' '}
                      </td>
                      <td className={`px-2 py-0.5 whitespace-pre-wrap ${
                        line.type === 'added' ? 'text-green-300' :
                        line.type === 'removed' ? 'text-red-300' :
                        'text-gray-400'
                      }`}>
                        {line.type === 'added' ? line.rightLine : line.leftLine}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        <div>
          <div className="text-xs font-medium text-gray-400 mb-1">Saved Comparer Items</div>
          {items.length === 0 ? (
            <div className="text-xs text-gray-500">No saved items.</div>
          ) : (
            <div className="space-y-1">
              {items.map((item) => (
                <div
                  key={item.id}
                  className="bg-gray-900 border border-gray-800 rounded p-2 flex items-center gap-2 text-xs"
                >
                  <span className="text-gray-300 font-medium">{item.left_label || 'Left'}</span>
                  <span className="text-gray-500">vs</span>
                  <span className="text-gray-300 font-medium">{item.right_label || 'Right'}</span>
                  <span className="text-gray-500 ml-auto text-xs">
                    {new Date(item.created_at).toLocaleString()}
                  </span>
                  <button
                    onClick={() => handleCompareSaved(item)}
                    className="p-1 text-purple-400 hover:text-purple-300"
                    title="Compare"
                  >
                    <GitCompare size={12} />
                  </button>
                  <button
                    onClick={() => handleDelete(item.id)}
                    className="p-1 text-red-400 hover:text-red-300"
                    title="Delete"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, ArrowRight, GitBranch, RefreshCw, Waypoints } from 'lucide-react'
import {
  getAttackPath,
  type AttackPathEdge,
  type AttackPathGraph,
  type AttackPathNode,
} from '../../api/endpoints/attackPath'
import { useSessionStore } from '../../store/useSessionStore'

const SEVERITY_COLUMNS = ['info', 'low', 'medium', 'high', 'critical'] as const
const SEVERITY_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

const SEVERITY_STYLE: Record<string, { fill: string; stroke: string; text: string; badge: string }> = {
  critical: { fill: 'rgba(248,113,113,0.10)', stroke: '#b91c1c', text: '#fca5a5', badge: 'bg-red-400/10 text-red-400' },
  high: { fill: 'rgba(251,146,60,0.10)', stroke: '#c2410c', text: '#fdba74', badge: 'bg-orange-400/10 text-orange-400' },
  medium: { fill: 'rgba(250,204,21,0.10)', stroke: '#a16207', text: '#fde047', badge: 'bg-yellow-400/10 text-yellow-400' },
  low: { fill: 'rgba(96,165,250,0.10)', stroke: '#1d4ed8', text: '#93c5fd', badge: 'bg-blue-400/10 text-blue-400' },
  info: { fill: 'rgba(156,163,175,0.10)', stroke: '#4b5563', text: '#d1d5db', badge: 'bg-gray-400/10 text-gray-400' },
}

const REASON_LABEL: Record<string, string> = {
  same_request: 'Same HTTP exchange',
  exposure_enables_finding: 'Exposure enables finding',
}

const REASON_COLOR: Record<string, string> = {
  same_request: '#a855f7',
  exposure_enables_finding: '#f59e0b',
}

const NODE_W = 220
const NODE_H = 66
const GAP_X = 90
const GAP_Y = 18
const PAD = 24
const MAX_RENDERED_NODES = 100
const MAX_LISTED_EDGES = 40

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value
}

function severityStyle(node: AttackPathNode) {
  return SEVERITY_STYLE[node.severity] || SEVERITY_STYLE.info
}

interface Position {
  node: AttackPathNode
  x: number
  y: number
}

interface Layout {
  positions: Map<string, Position>
  edges: Array<AttackPathEdge & { path: string; color: string }>
  width: number
  height: number
  hidden: number
}

function buildLayout(graph: AttackPathGraph): Layout {
  const visible = graph.nodes.slice(0, MAX_RENDERED_NODES)
  const columns = new Map<number, AttackPathNode[]>()
  for (const node of visible) {
    const column = SEVERITY_RANK[node.severity] ?? 0
    const list = columns.get(column) || []
    list.push(node)
    columns.set(column, list)
  }

  const positions = new Map<string, Position>()
  let width = 0
  for (const [column, nodes] of columns) {
    const x = PAD + column * (NODE_W + GAP_X)
    nodes.forEach((node, index) => {
      positions.set(node.id, { node, x, y: PAD + index * (NODE_H + GAP_Y) })
    })
    width = Math.max(width, x + NODE_W + PAD)
  }

  let maxColumn = 1
  for (const nodes of columns.values()) maxColumn = Math.max(maxColumn, nodes.length)
  const height = PAD * 2 + maxColumn * (NODE_H + GAP_Y) - GAP_Y

  const edges: Layout['edges'] = []
  for (const edge of graph.edges) {
    const source = positions.get(edge.source)
    const target = positions.get(edge.target)
    if (!source || !target) continue
    const x1 = source.x + NODE_W
    const y1 = source.y + NODE_H / 2
    const x2 = target.x
    const y2 = target.y + NODE_H / 2
    const bend = Math.max(50, Math.abs(x2 - x1) / 2)
    const path = `M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`
    edges.push({ ...edge, path, color: REASON_COLOR[edge.reason] || '#6b7280' })
  }

  return {
    positions,
    edges,
    width: Math.max(width, 520),
    height: Math.max(height, 220),
    hidden: Math.max(0, graph.nodes.length - visible.length),
  }
}

export function AttackPath() {
  const { activeSessionId } = useSessionStore()
  const [graph, setGraph] = useState<AttackPathGraph | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const load = async () => {
    setLoading(true)
    setError('')
    setSelectedId(null)
    try {
      setGraph(await getAttackPath(activeSessionId))
    } catch (e: any) {
      setError(e.response?.data?.detail || e.message || 'Could not load the attack path')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [activeSessionId])

  const layout = useMemo(() => (graph ? buildLayout(graph) : null), [graph])

  const selected = selectedId && graph
    ? graph.nodes.find((node) => node.id === selectedId) || null
    : null

  const relatedEdges = useMemo(() => {
    if (!graph || !selectedId) return { outgoing: [], incoming: [] }
    return {
      outgoing: graph.edges.filter((edge) => edge.source === selectedId),
      incoming: graph.edges.filter((edge) => edge.target === selectedId),
    }
  }, [graph, selectedId])

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const node of graph?.nodes || []) {
      counts[node.severity] = (counts[node.severity] || 0) + 1
    }
    return counts
  }, [graph])

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-5 overflow-y-auto h-full">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <GitBranch className="w-6 h-6 text-purple-400" />
          <div>
            <h1 className="text-xl font-bold text-gray-100">Attack Path</h1>
            <p className="text-xs text-gray-500 mt-0.5">
              How findings chain into reachable impact for the active session.
            </p>
          </div>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium text-gray-400 hover:text-gray-200 hover:bg-gray-800 disabled:opacity-50 transition-colors"
        >
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {graph && graph.nodes.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-[11px]">
          <span className="px-2 py-0.5 rounded-full bg-purple-400/10 text-purple-300 border border-purple-800/40">
            {graph.nodes.length} finding{graph.nodes.length === 1 ? '' : 's'}
          </span>
          <span className="px-2 py-0.5 rounded-full bg-gray-800 text-gray-400 border border-gray-700">
            {graph.edges.length} connection{graph.edges.length === 1 ? '' : 's'}
          </span>
          {SEVERITY_COLUMNS.slice().reverse().map((severity) =>
            severityCounts[severity] ? (
              <span
                key={severity}
                className={`px-2 py-0.5 rounded-full border border-gray-800 ${SEVERITY_STYLE[severity].badge}`}
              >
                {severityCounts[severity]} {severity}
              </span>
            ) : null,
          )}
        </div>
      )}

      {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-3">{error}</div>}

      {loading ? (
        <div className="text-center py-16 text-gray-500 text-sm">Building attack path…</div>
      ) : !graph || graph.nodes.length === 0 ? (
        <div className="text-center py-16 border border-dashed border-gray-800 rounded-lg">
          <Waypoints className="w-9 h-9 text-gray-700 mx-auto mb-2" />
          <p className="text-sm text-gray-400">No findings for this session yet.</p>
          <p className="text-xs text-gray-600 mt-1">
            Run passive or active scanning; the graph updates as findings are stored.
          </p>
        </div>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-4 text-[10px] text-gray-500">
            <span className="flex items-center gap-1.5">
              <span className="inline-block w-4 border-t-2 border-purple-500" /> same exchange
            </span>
            <span className="flex items-center gap-1.5">
              <span className="inline-block w-4 border-t-2 border-amber-500" /> exposure enables finding
            </span>
            <span>Left = reconnaissance, right = impact. Click a node for details.</span>
          </div>

          <div className="border border-gray-800 rounded-lg bg-gray-950/60 overflow-auto max-h-[62vh]">
            {layout && (
              <svg
                width={layout.width}
                height={layout.height}
                role="img"
                aria-label="Attack path graph"
                className="block"
              >
                <defs>
                  {Object.entries(REASON_COLOR).map(([reason, color]) => (
                    <marker
                      key={reason}
                      id={`arrow-${reason}`}
                      viewBox="0 0 10 10"
                      refX="9"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 0 L 10 5 L 0 10 z" fill={color} />
                    </marker>
                  ))}
                </defs>

                {SEVERITY_COLUMNS.map((severity, index) => (
                  <text
                    key={severity}
                    x={PAD + index * (NODE_W + GAP_X)}
                    y={14}
                    className="fill-gray-600"
                    fontSize={10}
                    letterSpacing="0.08em"
                  >
                    {severity.toUpperCase()}
                  </text>
                ))}

                {layout.edges.map((edge) => {
                  const active =
                    !selectedId || edge.source === selectedId || edge.target === selectedId
                  return (
                    <path
                      key={`${edge.source}-${edge.target}-${edge.reason}`}
                      d={edge.path}
                      fill="none"
                      stroke={edge.color}
                      strokeWidth={1.5}
                      strokeOpacity={active ? 0.8 : 0.12}
                      markerEnd={`url(#arrow-${edge.reason})`}
                    />
                  )
                })}

                {[...layout.positions.values()].map(({ node, x, y }) => {
                  const style = severityStyle(node)
                  const isSelected = node.id === selectedId
                  return (
                    <g
                      key={node.id}
                      transform={`translate(${x}, ${y})`}
                      onClick={() => setSelectedId(selectedId === node.id ? null : node.id)}
                      className="cursor-pointer"
                      role="button"
                      tabIndex={0}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          setSelectedId(selectedId === node.id ? null : node.id)
                        }
                      }}
                    >
                      <title>{`${node.title} — ${node.severity}${node.host ? ` — ${node.host}` : ''}`}</title>
                      <rect
                        width={NODE_W}
                        height={NODE_H}
                        rx={8}
                        fill={style.fill}
                        stroke={isSelected ? '#a855f7' : style.stroke}
                        strokeWidth={isSelected ? 2 : 1}
                      />
                      <text x={12} y={20} fontSize={10} fill={style.text} fontWeight={600}>
                        {node.severity.toUpperCase()}
                      </text>
                      {node.cwe && (
                        <text x={NODE_W - 12} y={20} fontSize={9} fill="#6b7280" textAnchor="end">
                          {node.cwe}
                        </text>
                      )}
                      <text x={12} y={39} fontSize={11} fill="#e5e7eb">
                        {truncate(node.title, 32)}
                      </text>
                      <text x={12} y={55} fontSize={9} fill="#9ca3af">
                        {truncate(node.host || 'no host', 34)}
                      </text>
                    </g>
                  )
                })}
              </svg>
            )}
          </div>

          {layout && layout.hidden > 0 && (
            <div className="text-[10px] text-gray-500">
              Showing the {MAX_RENDERED_NODES} highest-severity findings; {layout.hidden} more are
              hidden. Narrow the session or triage findings to see the rest.
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="border border-gray-800 rounded-lg bg-gray-900/60">
              <div className="px-3 py-2 border-b border-gray-800 text-xs font-medium text-gray-300">
                {selected ? 'Selected finding' : 'Connections'}
              </div>
              {selected ? (
                <div className="p-3 space-y-2 text-xs">
                  <div className="flex items-center gap-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${severityStyle(selected).badge}`}>
                      {selected.severity.toUpperCase()}
                    </span>
                    <span className="text-gray-200">{selected.title}</span>
                  </div>
                  <div className="text-gray-500 font-mono text-[11px]">
                    {selected.host || 'no host'}
                    {selected.cwe ? ` · ${selected.cwe}` : ''}
                  </div>
                  {selected.request_id && (
                    <div className="text-gray-600 font-mono text-[10px]">
                      request {selected.request_id}
                    </div>
                  )}
                  <div className="text-gray-400">
                    {relatedEdges.incoming.length} incoming, {relatedEdges.outgoing.length} outgoing
                  </div>
                  <button
                    onClick={() => setSelectedId(null)}
                    className="text-[11px] text-purple-400 hover:text-purple-300"
                  >
                    Clear selection
                  </button>
                </div>
              ) : (
                <div className="p-3 space-y-1.5 max-h-64 overflow-y-auto">
                  {graph.edges.length === 0 ? (
                    <p className="text-xs text-gray-500">
                      No chains detected yet. Findings connect when they share an exchange or when
                      a lower-severity exposure precedes a severe finding on the same host.
                    </p>
                  ) : (
                    graph.edges.slice(0, MAX_LISTED_EDGES).map((edge) => {
                      const source = graph.nodes.find((node) => node.id === edge.source)
                      const target = graph.nodes.find((node) => node.id === edge.target)
                      if (!source || !target) return null
                      return (
                        <button
                          key={`${edge.source}-${edge.target}-${edge.reason}`}
                          onClick={() => setSelectedId(edge.source)}
                          className="w-full text-left flex items-start gap-2 rounded px-2 py-1.5 hover:bg-gray-800/60"
                        >
                          <span
                            className="mt-1 w-1.5 h-1.5 rounded-full shrink-0"
                            style={{ backgroundColor: REASON_COLOR[edge.reason] || '#6b7280' }}
                          />
                          <span className="text-[11px] text-gray-300">
                            {truncate(source.title, 28)}
                            <ArrowRight size={10} className="inline mx-1 text-gray-600" />
                            {truncate(target.title, 28)}
                            <span className="block text-[10px] text-gray-600">
                              {REASON_LABEL[edge.reason] || edge.reason}
                            </span>
                          </span>
                        </button>
                      )
                    })
                  )}
                </div>
              )}
            </div>

            <div className="border border-gray-800 rounded-lg bg-gray-900/60 p-3 text-xs text-gray-400 space-y-2">
              <div className="flex items-center gap-2 text-gray-300 font-medium">
                <AlertTriangle size={13} className="text-amber-400" /> How to read this
              </div>
              <p>
                Nodes are stored findings, not guesses. An edge is only drawn when two findings
                share the same HTTP exchange, or when a lower-severity exposure on the same host
                precedes a more severe finding.
              </p>
              <p>
                The graph is bounded to the highest-severity findings and a fixed number of edges
                per host so a long-lived session cannot exhaust the API process.
              </p>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

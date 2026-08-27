import { useRef, useMemo, useCallback, useState, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import { useReactTable, getCoreRowModel, flexRender, createColumnHelper } from '@tanstack/react-table'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Radio, Loader2 } from 'lucide-react'
import { NyxRequest } from '../../types'
import { apiClient } from '../../api/client'
import { useProxyStore } from '../../store/useProxyStore'
import { FilterBar } from './FilterBar'
import { RequestDetail } from './RequestDetail'
import { useFuzzerStore } from '../../store/useFuzzerStore'
import { useAutoExploitStore } from '../../store/useAutoExploitStore'
import { useSessionStore } from '../../store/useSessionStore'

const STATUS_COLOR: Record<number, string> = {
  2: 'text-green-400',
  3: 'text-blue-400',
  4: 'text-yellow-400',
  5: 'text-red-400',
}

const columnHelper = createColumnHelper<NyxRequest>()

export function ProxyLog() {
  const navigate = useNavigate()
  const [captureActive, setCaptureActive] = useState(true)
  const [sendingToRepeater, setSendingToRepeater] = useState<string | null>(null)

  const { requests, selectedId, filter, select } = useProxyStore()
  const { setFuzzerTarget } = useFuzzerStore()
  const { setTarget: setAutoExploitTarget } = useAutoExploitStore()
  const [openMenuId, setOpenMenuId] = useState<string | null>(null)
  const [menuAnchor, setMenuAnchor] = useState<{ x: number; y: number } | null>(null)
  
  const _activeSessionId = useSessionStore((s) => s.activeSessionId)

  // Close menu when clicking outside
  useEffect(() => {
    const handleOutsideClick = () => setOpenMenuId(null)
    window.addEventListener('click', handleOutsideClick)
    return () => window.removeEventListener('click', handleOutsideClick)
  }, [])

  // Fetch history is handled globally in useWebSocket (mounted in App) so the
  // proxy store is populated for every module, not only when ProxyLog mounts.

  useEffect(() => {
    apiClient.get('/api/proxy/capture')
      .then(r => setCaptureActive(r.data.capture_active))
      .catch(() => {})
  }, [])

  const toggleCapture = () => {
    const next = !captureActive
    setCaptureActive(next)
    apiClient.post('/api/proxy/capture', { active: next }).catch(() => setCaptureActive(!next))
    if ((window as any).nyxDesktop) {
      (window as any).nyxDesktop.setProxyCapture(next)
    }
  }

  const sendToRepeater = useCallback(async (req: NyxRequest) => {
    const reqId = req.id
    setSendingToRepeater(reqId)
    try {
      const res = await apiClient.post('/api/repeater/tabs', {
        request_data: {
          method: req.method,
          url: req.url,
          headers: req.request_headers,
          body: req.request_body,
        },
      })
      setSendingToRepeater(null)
      navigate(`/repeater?tab=${res.data.id}`)
    } catch (err) {
      setSendingToRepeater(null)
      console.error('[sendToRepeater] Failed:', err)
    }
  }, [navigate])

  const columns = useMemo(() => [
    columnHelper.accessor('method', {
      header: 'Method',
      size: 70,
      cell: (info) => (
        <span className="font-mono text-xs font-bold text-purple-400">
          {info.getValue()}
        </span>
      ),
    }),
    columnHelper.accessor('host', {
      header: 'Host',
      size: 200,
    }),
    columnHelper.accessor('path', {
      header: 'Path',
      size: 300,
    }),
    columnHelper.accessor('response_status', {
      header: 'Status',
      size: 70,
      cell: (info) => {
        const s = info.getValue()
        const color = s ? STATUS_COLOR[Math.floor(s / 100)] || '' : 'text-gray-500'
        return <span className={`font-mono ${color}`}>{s ?? '…'}</span>
      },
    }),
    columnHelper.accessor('timestamp', {
      header: 'Time',
      size: 100,
      cell: (info) => {
        const t = info.getValue()
        if (!t) return <span className="text-gray-600">—</span>
        const d = new Date(t)
        if (isNaN(d.getTime())) return <span className="text-gray-600">—</span>
        const now = Date.now()
        const diff = now - d.getTime()
        const abs = Math.abs(diff)
        const fmt = (n: number, unit: string) => `${n}${unit}`
        const when =
          abs < 60_000 ? fmt(Math.max(1, Math.round(abs / 1000)), 's')
          : abs < 3_600_000 ? fmt(Math.round(abs / 60_000), 'm')
          : abs < 86_400_000 ? fmt(Math.round(abs / 3_600_000), 'h')
          : fmt(Math.round(abs / 86_400_000), 'd')
        const title = d.toLocaleString()
        return (
          <span className="font-mono text-gray-400" title={title}>
            {diff >= 0 ? `${when} ago` : `in ${when}`}
          </span>
        )
      },
    }),
    columnHelper.accessor('response_size_bytes', {
      header: 'Size',
      size: 80,
      cell: (info) => {
        const b = info.getValue()
        return b != null ? `${(b / 1024).toFixed(1)}KB` : '—'
      },
    }),
    columnHelper.accessor('response_time_ms', {
      header: 'Time',
      size: 70,
      cell: (info) => {
        const t = info.getValue()
        return t != null ? `${t}ms` : '—'
      },
    }),
    columnHelper.display({
      id: 'actions',
      header: '',
      size: 60,
      cell: (info) => {
        const req = info.row.original
        const isMenuOpen = openMenuId === req.id

        return (
          <div className="relative" onClick={(e) => e.stopPropagation()}>
            <button
              onClick={(e) => {
                e.stopPropagation()
                if (isMenuOpen) {
                  setOpenMenuId(null)
                  return
                }
                const rect = e.currentTarget.getBoundingClientRect()
                setMenuAnchor({ x: rect.right, y: rect.bottom + 4 })
                setOpenMenuId(req.id)
              }}
              className="text-gray-500 hover:text-gray-300 px-2 py-1 transition-colors"
            >
              ⋮
            </button>
          </div>
        )
      },
    }),
  ], [openMenuId, sendToRepeater])

  const filtered = useMemo(
    () =>
      requests.filter((r) => {
        if (filter.method && r.method !== filter.method) return false
        if (filter.host && !r.host.includes(filter.host)) return false
        if (filter.status && r.response_status !== filter.status) return false
        if (filter.flagged && !r.is_flagged) return false
        if (filter.search && !r.url.includes(filter.search)) return false
        return true
      }),
    [requests, filter],
  )

  const table = useReactTable({
    data: filtered,
    columns,
    getCoreRowModel: getCoreRowModel(),
  })

  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 32,
    overscan: 20,
  })

  const selectedRequest = requests.find((r) => r.id === selectedId)

  return (
    <div className="flex h-full">
      <div className="flex flex-col flex-1 min-w-0">
        <FilterBar captureActive={captureActive} onToggleCapture={toggleCapture} />
        {!captureActive && requests.length === 0 && (
          <div className="flex flex-col items-center justify-center flex-1 text-gray-500 p-4">
            <Radio size={32} className="mb-2 opacity-50" />
            <p className="text-sm font-medium">Traffic capture is paused</p>
            <p className="text-xs mt-1">Click <strong>Capture ON</strong> above to start logging requests</p>
          </div>
        )}
        {captureActive && requests.length === 0 && (
          <div className="flex flex-col items-center justify-center flex-1 text-gray-500 p-4 gap-2">
            <Radio size={36} className="text-green-400 animate-pulse" />
            <p className="text-sm font-medium text-gray-300">Proxy is listening on port 8080</p>
            <p className="text-xs text-gray-500">Waiting for traffic…</p>
            <div className="mt-2 bg-gray-900 border border-gray-800 rounded-lg p-3 text-left text-[11px] text-gray-400 space-y-1 max-w-xs">
              <p className="text-gray-300 font-medium text-xs mb-1">📌 To get started:</p>
              <p>• <strong>Browser:</strong> configure proxy to <code className="text-purple-300">127.0.0.1:8080</code></p>
              <p>• <strong>MITM tab:</strong> scan a network and start intercepting a target</p>
              <p>• <strong>Stealth Mode:</strong> set a target device's proxy to <code className="text-purple-300">NYX_IP:8080</code></p>
            </div>
          </div>
        )}
        {(!captureActive && requests.length > 0) && (
          <div className="px-2 py-1 bg-yellow-500/10 border-b border-yellow-500/20 text-[10px] text-yellow-400 flex items-center gap-2">
            <Radio size={10} /> Capture is paused — existing requests shown, new traffic not logged
          </div>
        )}
        <div ref={parentRef} className="overflow-auto flex-1">
          <div style={{ height: virtualizer.getTotalSize() }} className="relative">
            {virtualizer.getVirtualItems().map((virtualRow) => {
              const row = table.getRowModel().rows[virtualRow.index]
              const req = row.original
              return (
                <div
                  key={req.id}
                  style={{ transform: `translateY(${virtualRow.start}px)` }}
                  className={`absolute w-full flex items-center h-8 px-2 cursor-pointer border-b border-gray-900 hover:bg-gray-800 text-xs ${
                    selectedId === req.id ? 'bg-gray-700' : ''
                  } ${req.is_flagged ? 'border-l-2 border-l-yellow-400' : ''}`}
                  role="button"
                  tabIndex={0}
                  aria-pressed={selectedId === req.id}
                  aria-label={`${req.method} ${req.url} — ${req.response_status ?? 'pending'}`}
                  onClick={() => select(selectedId === req.id ? null : req.id)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      select(selectedId === req.id ? null : req.id)
                    }
                  }}
                >
                  {row.getVisibleCells().map((cell) => (
                    <div
                      key={cell.id}
                      style={{ width: cell.column.getSize() }}
                      className="truncate pr-2"
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </div>
                  ))}
                </div>
              )
            })}
          </div>
        </div>
      </div>
      {selectedRequest && (
        <div className="w-1/2 border-l border-gray-800">
          <RequestDetail request={selectedRequest} />
        </div>
      )}
      {openMenuId &&
        menuAnchor &&
        createPortal(
          (() => {
            const menuReq = requests.find((r) => r.id === openMenuId)
            if (!menuReq) return null
            const isSending = sendingToRepeater === menuReq.id
            const flip = menuAnchor.x > window.innerWidth - 176
            return (
              <div
                style={{
                  position: 'fixed',
                  left: flip ? menuAnchor.x - 160 : menuAnchor.x,
                  top: menuAnchor.y,
                  zIndex: 9999,
                }}
                onClick={(e) => e.stopPropagation()}
                className="w-40 bg-gray-800 border border-gray-700 rounded shadow-xl flex flex-col py-1 text-xs"
              >
                <button
                  className="text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200 flex items-center justify-between"
                  disabled={isSending}
                  onClick={() => {
                    setOpenMenuId(null)
                    sendToRepeater(menuReq)
                  }}
                >
                  Send to Repeater
                  {isSending && <Loader2 className="w-3 h-3 animate-spin text-purple-400" />}
                </button>
                <button
                  className="text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200"
                  onClick={() => {
                    setOpenMenuId(null)
                    const body = menuReq.request_body ? `\r\n${menuReq.request_body}` : ''
                    setFuzzerTarget(menuReq.id, `${menuReq.method} ${menuReq.path} HTTP/1.1\r\nHost: ${menuReq.host}\r\n${body}`)
                    navigate('/fuzzer')
                  }}
                >
                  Send to Fuzzer
                </button>
                <button
                  className="text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200"
                  onClick={() => {
                    setOpenMenuId(null)
                    setAutoExploitTarget({
                      type: 'request',
                      id: menuReq.id,
                      url: menuReq.url,
                      method: menuReq.method
                    })
                    navigate('/auto-exploit')
                  }}
                >
                  Send to Auto-Exploit
                </button>
              </div>
            )
          })(),
          document.body
        )}
    </div>
  )
}

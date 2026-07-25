import { useRef, useMemo, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useReactTable, getCoreRowModel, flexRender, createColumnHelper } from '@tanstack/react-table'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ExternalLink } from 'lucide-react'
import { NyxRequest } from '../../types'
import { apiClient } from '../../api/client'
import { useProxyStore } from '../../store/useProxyStore'
import { FilterBar } from './FilterBar'
import { RequestDetail } from './RequestDetail'

const STATUS_COLOR: Record<number, string> = {
  2: 'text-green-400',
  3: 'text-blue-400',
  4: 'text-yellow-400',
  5: 'text-red-400',
}

const columnHelper = createColumnHelper<NyxRequest>()

export function ProxyLog() {
  const navigate = useNavigate()

  const { requests, selectedId, filter, select } = useProxyStore()

  const sendToRepeater = useCallback(async (req: NyxRequest) => {
    try {
      await apiClient.post('/api/repeater/tabs', {
        method: req.method,
        url: req.url,
        headers: req.request_headers,
        body: req.request_body,
      })
      navigate('/repeater')
    } catch {
      // silently fail
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
      size: 40,
      cell: (info) => {
        const req = info.row.original
        return (
          <button
            onClick={(e) => {
              e.stopPropagation()
              sendToRepeater(req)
            }}
            className="text-gray-500 hover:text-purple-400 transition-colors"
            title="Send to Repeater"
          >
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        )
      },
    }),
  ], [sendToRepeater])

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
        <FilterBar />
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
                  onClick={() => select(selectedId === req.id ? null : req.id)}
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
    </div>
  )
}

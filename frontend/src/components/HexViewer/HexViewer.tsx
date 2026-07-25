import { useState, useMemo, useRef, useCallback, useEffect } from 'react'
import { Search } from 'lucide-react'

interface HexViewerProps {
  data: string
  highlightStart?: number
  highlightEnd?: number
  readOnly?: boolean
  onByteClick?: (offset: number, byte: number) => void
}

interface TooltipInfo {
  x: number
  y: number
  offset: number
  byte: number
}

const BYTES_PER_ROW = 16

export function HexViewer({
  data,
  highlightStart,
  highlightEnd,
  readOnly = true,
  onByteClick,
}: HexViewerProps) {
  const rawBytes = useMemo(() => {
    const encoder = new TextEncoder()
    return encoder.encode(data)
  }, [data])

  const rows = useMemo(() => {
    const result: { offset: number; bytes: number[] }[] = []
    for (let i = 0; i < rawBytes.length; i += BYTES_PER_ROW) {
      result.push({
        offset: i,
        bytes: Array.from(rawBytes.slice(i, i + BYTES_PER_ROW)),
      })
    }
    return result
  }, [rawBytes])

  const [tooltip, setTooltip] = useState<TooltipInfo | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<number[]>([])
  const [currentSearchIdx, setCurrentSearchIdx] = useState(0)
  const [showSearch, setShowSearch] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  const searchBytes = useMemo(() => {
    const q = searchQuery.replace(/\s+/g, '')
    if (!q || q.length < 2) return null
    const bytes: number[] = []
    for (let i = 0; i < q.length; i += 2) {
      const hex = q.slice(i, i + 2)
      if (hex.length === 2) bytes.push(parseInt(hex, 16))
    }
    return bytes.length > 0 ? bytes : null
  }, [searchQuery])

  useEffect(() => {
    if (!searchBytes || searchBytes.length === 0) {
      setSearchResults([])
      return
    }
    const positions: number[] = []
    for (let i = 0; i <= rawBytes.length - searchBytes.length; i++) {
      let match = true
      for (let j = 0; j < searchBytes.length; j++) {
        if (rawBytes[i + j] !== searchBytes[j]) { match = false; break }
      }
      if (match) positions.push(i)
    }
    setSearchResults(positions)
    setCurrentSearchIdx(0)
  }, [searchBytes, rawBytes])

  const handleByteClick = useCallback(
    (e: React.MouseEvent, offset: number, byte: number) => {
      const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
      setTooltip({ x: rect.left, y: rect.bottom + 4, offset, byte })
      onByteClick?.(offset, byte)
    },
    [onByteClick]
  )

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault()
        setShowSearch((s) => !s)
      }
      if (e.key === 'Escape') {
        setShowSearch(false)
        setSearchQuery('')
      }
    },
    []
  )

  const scrollToSearch = useCallback(
    (idx: number) => {
      if (searchResults.length === 0) return
      const pos = searchResults[idx]
      const rowIndex = Math.floor(pos / BYTES_PER_ROW)
      const container = containerRef.current
      if (container) {
        const rowEl = container.querySelector(`[data-row="${rowIndex}"]`)
        rowEl?.scrollIntoView({ behavior: 'smooth', block: 'center' })
      }
    },
    [searchResults]
  )

  const isHighlighted = useCallback(
    (offset: number) => {
      if (highlightStart === undefined || highlightEnd === undefined) return false
      return offset >= highlightStart && offset < highlightEnd
    },
    [highlightStart, highlightEnd]
  )

  const isSearchMatch = useCallback(
    (offset: number) => {
      return searchResults.includes(offset)
    },
    [searchResults]
  )

  const isCurrentSearch = useCallback(
    (offset: number) => {
      return searchResults.length > 0 && searchResults[currentSearchIdx] === offset
    },
    [searchResults, currentSearchIdx]
  )

  return (
    <div className="font-mono text-xs" onKeyDown={handleKeyDown} tabIndex={0}>
      {showSearch && (
        <div className="flex items-center gap-2 p-2 bg-gray-800 border-b border-gray-700">
          <Search size={14} className="text-gray-400" />
          <input
            className="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-gray-200 w-48 outline-none focus:border-purple-500"
            placeholder="Hex bytes (e.g. 48656c6c6f)..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            autoFocus
          />
          {searchResults.length > 0 && (
            <span className="text-gray-400">
              {currentSearchIdx + 1}/{searchResults.length}
            </span>
          )}
          {searchResults.length > 0 && (
            <div className="flex gap-1">
              <button
                className="px-1.5 py-0.5 bg-gray-700 rounded hover:bg-gray-600 text-gray-300"
                onClick={() => {
                  const next = (currentSearchIdx - 1 + searchResults.length) % searchResults.length
                  setCurrentSearchIdx(next)
                  scrollToSearch(next)
                }}
              >
                &uarr;
              </button>
              <button
                className="px-1.5 py-0.5 bg-gray-700 rounded hover:bg-gray-600 text-gray-300"
                onClick={() => {
                  const next = (currentSearchIdx + 1) % searchResults.length
                  setCurrentSearchIdx(next)
                  scrollToSearch(next)
                }}
              >
                &darr;
              </button>
            </div>
          )}
          {searchQuery && searchResults.length === 0 && (
            <span className="text-red-400">No matches</span>
          )}
        </div>
      )}

      <div
        ref={containerRef}
        className="overflow-auto max-h-96"
        onClick={() => setTooltip(null)}
      >
        <table className="w-full border-collapse">
          <thead>
            <tr className="text-gray-500 border-b border-gray-800">
              <th className="text-left px-2 py-1 w-32">Offset</th>
              <th className="text-left px-2 py-1">
                <span className="text-blue-400">00 01 02 03 04 05 06 07</span>
                <span className="text-gray-600 mx-1">&nbsp;</span>
                <span className="text-blue-400">08 09 0a 0b 0c 0d 0e 0f</span>
              </th>
              <th className="text-left px-2 py-1 w-24">ASCII</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.offset}
                data-row={Math.floor(row.offset / BYTES_PER_ROW)}
                className="hover:bg-gray-800/40"
              >
                <td className="text-gray-500 px-2 py-0.5 select-none">
                  {row.offset.toString(16).padStart(8, '0')}
                </td>
                <td className="px-2 py-0.5">
                  <span className="text-cyan-300">
                    {row.bytes
                      .slice(0, 8)
                      .map((b, i) => {
                        const off = row.offset + i
                        const hl = isHighlighted(off)
                        const sm = isSearchMatch(off)
                        const cs = isCurrentSearch(off)
                        let cls = 'cursor-pointer rounded px-0.5 '
                        if (cs) cls += 'bg-yellow-600 text-white '
                        else if (sm) cls += 'bg-yellow-800/60 text-yellow-200 '
                        else if (hl) cls += 'bg-purple-700/40 '
                        else cls += 'hover:bg-gray-700 '
                        return (
                          <span
                            key={i}
                            className={cls}
                            onClick={(e) => handleByteClick(e, off, b)}
                          >
                            {b.toString(16).padStart(2, '0')}
                          </span>
                        )
                      })}
                  </span>
                  <span className="text-gray-600 mx-1"> </span>
                  <span className="text-cyan-300">
                    {row.bytes
                      .slice(8, 16)
                      .map((b, i) => {
                        const off = row.offset + 8 + i
                        const hl = isHighlighted(off)
                        const sm = isSearchMatch(off)
                        const cs = isCurrentSearch(off)
                        let cls = 'cursor-pointer rounded px-0.5 '
                        if (cs) cls += 'bg-yellow-600 text-white '
                        else if (sm) cls += 'bg-yellow-800/60 text-yellow-200 '
                        else if (hl) cls += 'bg-purple-700/40 '
                        else cls += 'hover:bg-gray-700 '
                        return (
                          <span
                            key={i}
                            className={cls}
                            onClick={(e) => handleByteClick(e, off, b)}
                          >
                            {b.toString(16).padStart(2, '0')}
                          </span>
                        )
                      })}
                  </span>
                </td>
                <td className="px-2 py-0.5">
                  {row.bytes.map((b, i) => {
                    const off = row.offset + i
                    const printable = b >= 32 && b < 127
                    const sm = isSearchMatch(off)
                    const cs = isCurrentSearch(off)
                    let cls = 'inline-block w-[1ch] text-center '
                    if (cs) cls += 'bg-yellow-600 text-white '
                    else if (sm) cls += 'bg-yellow-800/60 '
                    else if (printable) cls += 'text-green-400 '
                    else cls += 'text-red-500 '
                    return (
                      <span key={i} className={cls}>
                        {printable ? String.fromCharCode(b) : '.'}
                      </span>
                    )
                  })}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {tooltip && (
        <div
          className="fixed z-50 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-xs text-gray-200 shadow-xl pointer-events-none"
          style={{ left: tooltip.x, top: tooltip.y }}
        >
          <div className="font-semibold text-purple-400 mb-1">
            Offset 0x{tooltip.offset.toString(16).padStart(8, '0')}
          </div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-0.5">
            <span className="text-gray-500">Hex:</span>
            <span className="text-cyan-300 font-mono">
              0x{tooltip.byte.toString(16).padStart(2, '0')}
            </span>
            <span className="text-gray-500">Decimal:</span>
            <span>{tooltip.byte}</span>
            <span className="text-gray-500">Binary:</span>
            <span className="text-yellow-300">
              {tooltip.byte.toString(2).padStart(8, '0')}
            </span>
            <span className="text-gray-500">Char:</span>
            <span className={tooltip.byte >= 32 && tooltip.byte < 127 ? 'text-green-400' : 'text-red-400'}>
              {tooltip.byte >= 32 && tooltip.byte < 127
                ? String.fromCharCode(tooltip.byte)
                : '(non-printable)'}
            </span>
          </div>
        </div>
      )}
    </div>
  )
}

export default HexViewer

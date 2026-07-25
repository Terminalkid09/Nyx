import { useState, useEffect, useRef, useCallback } from 'react'
import { apiClient } from '../../api/client'
import { Activity, Play, Square, BarChart, Zap, AlertTriangle } from 'lucide-react'

type Tab = 'live' | 'manual'

interface AnalyzeResult {
  sample_count: number
  token_length: number
  char_entropy_bits_per_char: number
  estimated_total_bits: number
  bit_entropy: number
  verdict: string
  is_weak: boolean
  unique_tokens: number
  duplicates_found: number
  character_frequency: Record<string, number>
  positional_entropy: number[]
  byte_distribution: number[]
  consecutive_duplicates: { count: number; sample_positions: number[] }
  auto_correlation: { lag_1: number; anomaly_detected: boolean; note: string }
  fips_140_2: {
    tested: boolean
    reason?: string
    monobit?: { ones: number; pass: boolean }
    longest_run?: { length: number; pass: boolean }
    runs_count?: number
  }
}

interface Session {
  id: string
  name: string
}

export function Sequencer() {
  const [activeTab, setActiveTab] = useState<Tab>('manual')
  const [error, setError] = useState('')

  const [manualTokens, setManualTokens] = useState('')
  const [result, setResult] = useState<AnalyzeResult | null>(null)
  const [analyzing, setAnalyzing] = useState(false)

  const [sessions, setSessions] = useState<Session[]>([])
  const [selectedSession, setSelectedSession] = useState('')
  const [isCapturing, setIsCapturing] = useState(false)
  const [liveTokens, setLiveTokens] = useState<string[]>([])
  const [liveCount, setLiveCount] = useState(0)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    fetchSessions()
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  const fetchSessions = async () => {
    try {
      const { data } = await apiClient.get('/api/sessions')
      setSessions(data.sessions || data || [])
      if (data.sessions?.length > 0 && !selectedSession) {
        setSelectedSession(data.sessions[0].id)
      }
    } catch {
      // sessions endpoint may not exist yet
    }
  }

  const fetchLiveTokens = useCallback(async () => {
    if (!selectedSession) return
    try {
      const { data } = await apiClient.get(
        `/api/sequencer/live/tokens/${selectedSession}`
      )
      setLiveTokens(data.tokens || [])
      setLiveCount(data.count || 0)
    } catch {
      // ignore
    }
  }, [selectedSession])

  const handleStartCapture = async () => {
    if (!selectedSession) return
    setError('')
    try {
      await apiClient.post('/api/sequencer/live/start', {
        session_id: selectedSession,
      })
      setIsCapturing(true)
      fetchLiveTokens()
      pollRef.current = setInterval(fetchLiveTokens, 2000)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleStopCapture = async () => {
    if (!selectedSession) return
    try {
      await apiClient.post('/api/sequencer/live/stop', {
        session_id: selectedSession,
      })
      setIsCapturing(false)
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
      fetchLiveTokens()
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleClearTokens = async () => {
    if (!selectedSession) return
    try {
      await apiClient.post('/api/sequencer/live/clear', {
        session_id: selectedSession,
      })
      setLiveTokens([])
      setLiveCount(0)
      setResult(null)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleAnalyzeTokens = async (tokens: string[]) => {
    if (tokens.length < 100) {
      setError('Need at least 100 tokens for meaningful analysis.')
      return
    }
    setAnalyzing(true)
    setError('')
    try {
      const { data } = await apiClient.post('/api/sequencer/analyze', {
        tokens,
      })
      setResult(data)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setAnalyzing(false)
    }
  }

  const handleManualAnalyze = () => {
    const lines = manualTokens.split('\n').filter((l) => l.trim())
    handleAnalyzeTokens(lines)
  }

  const handleAnalyzeLive = () => {
    handleAnalyzeTokens(liveTokens)
  }

  const maxFreq = result
    ? Math.max(...Object.values(result.character_frequency), 1)
    : 1

  const maxByteDist = result
    ? Math.max(...result.byte_distribution, 1)
    : 1

  const chartBar = (value: number, max: number, color: string) => {
    const pct = Math.max((value / max) * 100, 1)
    return (
      <div
        className={`h-3 ${color} rounded-sm`}
        style={{ width: `${Math.min(pct, 100)}%` }}
        title={`${value}`}
      />
    )
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <Activity size={16} className="text-purple-400" />
        Sequencer
      </div>

      <div className="flex border-b border-gray-800 text-xs">
        {(
          [
            { key: 'live', label: 'Live Capture' },
            { key: 'manual', label: 'Manual' },
          ] as { key: Tab; label: string }[]
        ).map((tab) => (
          <button
            key={tab.key}
            className={`px-3 py-2 border-b-2 transition-colors ${
              activeTab === tab.key
                ? 'border-purple-500 text-purple-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
            onClick={() => {
              setActiveTab(tab.key)
              setError('')
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="flex-1 p-4 space-y-4 overflow-auto">
        {activeTab === 'live' && (
          <div className="space-y-3">
            <div className="flex gap-2 items-center">
              <select
                className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-200"
                value={selectedSession}
                onChange={(e) => setSelectedSession(e.target.value)}
              >
                <option value="">Select session...</option>
                {sessions.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name || s.id}
                  </option>
                ))}
              </select>

              {!isCapturing ? (
                <button
                  className="bg-green-700 hover:bg-green-800 px-3 py-1.5 rounded text-xs font-medium flex items-center gap-1.5 disabled:opacity-50"
                  onClick={handleStartCapture}
                  disabled={!selectedSession}
                >
                  <Play size={14} />
                  Start Capture
                </button>
              ) : (
                <button
                  className="bg-red-700 hover:bg-red-800 px-3 py-1.5 rounded text-xs font-medium flex items-center gap-1.5"
                  onClick={handleStopCapture}
                >
<Square size={14} />
                            Stop Capture
                </button>
              )}

              <button
                className="bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded text-xs font-medium"
                onClick={handleClearTokens}
                disabled={liveTokens.length === 0}
              >
                Clear
              </button>
            </div>

            {isCapturing && (
              <div className="flex items-center gap-2 text-xs text-green-400">
                <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                Capturing... Tokens collected: {liveCount}
              </div>
            )}

            {liveTokens.length > 0 && (
              <>
                <div className="max-h-40 overflow-y-auto bg-gray-900 border border-gray-800 rounded p-2 space-y-0.5">
                  {liveTokens.map((t, i) => (
                    <div
                      key={i}
                      className="text-xs font-mono text-gray-400 truncate hover:text-gray-200"
                      title={t}
                    >
                      <span className="text-gray-600 mr-2">#{i + 1}</span>
                      {t.length > 50 ? t.slice(0, 50) + '...' : t}
                    </div>
                  ))}
                </div>

                <button
                  className="bg-purple-600 hover:bg-purple-700 px-3 py-1.5 rounded text-xs font-medium flex items-center gap-1.5"
                  onClick={handleAnalyzeLive}
                  disabled={analyzing}
                >
                  <BarChart size={14} />
                  {analyzing ? 'Analyzing...' : `Analyze ${liveCount} Tokens`}
                </button>
              </>
            )}

            {!isCapturing && liveTokens.length === 0 && (
              <div className="text-xs text-gray-600 py-8 text-center">
                Select a session and click Start Capture to begin
              </div>
            )}
          </div>
        )}

        {activeTab === 'manual' && (
          <div className="space-y-3">
            <div>
              <label className="text-xs text-gray-500 block mb-1">
                Tokens (one per line, min 100)
              </label>
              <textarea
                className="w-full h-40 bg-gray-900 border border-gray-800 rounded p-2 text-xs font-mono text-gray-300 resize-none focus:border-purple-700 outline-none"
                value={manualTokens}
                onChange={(e) => setManualTokens(e.target.value)}
              />
            </div>
            <button
              className="bg-purple-600 hover:bg-purple-700 px-3 py-1.5 rounded text-xs font-medium flex items-center gap-1.5"
              onClick={handleManualAnalyze}
              disabled={analyzing}
            >
              <Zap size={14} />
              {analyzing ? 'Analyzing...' : 'Analyze'}
            </button>
          </div>
        )}

        {error && <div className="text-xs text-red-400">{error}</div>}

        {result && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2">
              <div
                className={`rounded p-3 border ${
                  result.is_weak
                    ? 'bg-red-900/20 border-red-800'
                    : 'bg-green-900/20 border-green-800'
                }`}
              >
                <div className="flex items-center gap-2">
                  <AlertTriangle
                    size={16}
                    className={result.is_weak ? 'text-red-400' : 'text-green-400'}
                  />
                  <span
                    className={`text-sm font-bold ${
                      result.is_weak ? 'text-red-400' : 'text-green-400'
                    }`}
                  >
                    {result.verdict}
                  </span>
                </div>
              </div>

              <div className="bg-gray-900 border border-gray-800 rounded p-3">
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                  <span className="text-gray-500">Samples</span>
                  <span className="text-gray-200">
                    {result.sample_count.toLocaleString()}
                  </span>
                  <span className="text-gray-500">Token length</span>
                  <span className="text-gray-200">{result.token_length}</span>
                  <span className="text-gray-500">Char entropy</span>
                  <span className="text-gray-200">
                    {result.char_entropy_bits_per_char} bits/char
                  </span>
                  <span className="text-gray-500">Est. bits</span>
                  <span className="text-gray-200">
                    {result.estimated_total_bits}
                  </span>
                  <span className="text-gray-500">Unique tokens</span>
                  <span className="text-gray-200">
                    {result.unique_tokens}
                  </span>
                  <span className="text-gray-500">Duplicates</span>
                  <span
                    className={
                      result.duplicates_found > 0
                        ? 'text-yellow-400'
                        : 'text-gray-200'
                    }
                  >
                    {result.duplicates_found}
                  </span>
                </div>
              </div>
            </div>

            {result.fips_140_2?.tested && (
              <div className="bg-gray-900 border border-gray-800 rounded p-3">
                <div className="text-xs font-medium text-gray-400 mb-2">
                  FIPS 140-2 Approximation
                </div>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div
                    className={`rounded p-2 ${
                      result.fips_140_2.monobit?.pass
                        ? 'bg-green-900/20 border border-green-800'
                        : 'bg-red-900/20 border border-red-800'
                    }`}
                  >
                    <div className="text-gray-500">Monobit</div>
                    <div className="text-gray-200">
                      {result.fips_140_2.monobit?.ones} ones
                    </div>
                    <div
                      className={
                        result.fips_140_2.monobit?.pass
                          ? 'text-green-400'
                          : 'text-red-400'
                      }
                    >
                      {result.fips_140_2.monobit?.pass ? 'PASS' : 'FAIL'}
                    </div>
                  </div>
                  <div
                    className={`rounded p-2 ${
                      result.fips_140_2.longest_run?.pass
                        ? 'bg-green-900/20 border border-green-800'
                        : 'bg-red-900/20 border border-red-800'
                    }`}
                  >
                    <div className="text-gray-500">Longest Run</div>
                    <div className="text-gray-200">
                      {result.fips_140_2.longest_run?.length} bits
                    </div>
                    <div
                      className={
                        result.fips_140_2.longest_run?.pass
                          ? 'text-green-400'
                          : 'text-red-400'
                      }
                    >
                      {result.fips_140_2.longest_run?.pass ? 'PASS' : 'FAIL'}
                    </div>
                  </div>
                  <div className="bg-gray-800 rounded p-2">
                    <div className="text-gray-500">Runs</div>
                    <div className="text-gray-200">
                      {result.fips_140_2.runs_count}
                    </div>
                  </div>
                </div>
              </div>
            )}

            <div className="bg-gray-900 border border-gray-800 rounded p-3">
              <div className="text-xs font-medium text-gray-400 mb-2">
                Character Frequency (top chars)
              </div>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {Object.entries(result.character_frequency)
                  .slice(0, 20)
                  .map(([char, count]) => (
                    <div key={char} className="flex items-center gap-2 text-xs">
                      <span className="w-5 text-center text-gray-400 font-mono">
                        {char === ' ' ? (
                          <span className="text-gray-600">&middot;</span>
                        ) : (
                          char
                        )}
                      </span>
                      <div className="flex-1">
                        {chartBar(count, maxFreq, 'bg-purple-600')}
                      </div>
                      <span className="w-12 text-right text-gray-500">
                        {count}
                      </span>
                    </div>
                  ))}
              </div>
            </div>

            {result.positional_entropy.length > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded p-3">
                <div className="text-xs font-medium text-gray-400 mb-2">
                  Positional Entropy
                </div>
                <div className="flex flex-wrap gap-0.5">
                  {result.positional_entropy.map((e, i) => {
                    const intensity = Math.min(e / 4, 1)
                    const r = Math.round(100 + (255 - 100) * (1 - intensity))
                    const g = Math.round(50 + (200 - 50) * intensity)
                    const b = Math.round(200 * (1 - intensity))
                    return (
                      <div
                        key={i}
                        className="w-5 h-5 rounded-sm flex items-center justify-center text-[9px] font-mono cursor-pointer hover:ring-1 hover:ring-purple-400"
                        style={{
                          backgroundColor: `rgb(${r}, ${g}, ${b})`,
                          color: intensity > 0.4 ? '#fff' : '#999',
                        }}
                        title={`Position ${i}: ${e.toFixed(2)} bits`}
                      >
                        {e.toFixed(1) !== '0.0' ? e.toFixed(1).replace('.', '') : '0'}
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {result.byte_distribution.length > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded p-3">
                <div className="text-xs font-medium text-gray-400 mb-2">
                  Byte Distribution (0-255)
                </div>
                <div className="flex items-end gap-px h-20">
                  {result.byte_distribution.map((count, i) => {
                    if (i % 8 !== 0) return null
                    const bucket = result.byte_distribution
                      .slice(i, i + 8)
                      .reduce((a, b) => a + b, 0)
                    const pct = Math.max((bucket / maxByteDist) * 100, 0.5)
                    return (
                      <div
                        key={i}
                        className="flex-1 bg-cyan-700 rounded-t"
                        style={{ height: `${pct}%` }}
                        title={`0x${i.toString(16).padStart(2, '0')}-0x${(i + 7).toString(16).padStart(2, '0')}: ${bucket}`}
                      />
                    )
                  })}
                </div>
              </div>
            )}

            {(result.consecutive_duplicates.count > 0 ||
              result.auto_correlation.anomaly_detected) && (
              <div className="bg-gray-900 border border-gray-800 rounded p-3">
                <div className="text-xs font-medium text-gray-400 mb-2">
                  Issues Detected
                </div>
                <div className="space-y-2 text-xs">
                  {result.consecutive_duplicates.count > 0 && (
                    <div className="flex items-start gap-2 text-yellow-400">
                      <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                      <div>
                        <span className="font-medium">
                          {result.consecutive_duplicates.count}
                        </span>{' '}
                        consecutive duplicate tokens found
                        {result.consecutive_duplicates.sample_positions.length >
                          0 && (
                          <span className="text-gray-500">
                            {' '}
                            (positions:{' '}
                            {result.consecutive_duplicates.sample_positions
                              .slice(0, 5)
                              .join(', ')}
                            ...)
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                  {result.auto_correlation.anomaly_detected && (
                    <div className="flex items-start gap-2 text-yellow-400">
                      <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                      <div>
                        Autocorrelation (lag-1):{' '}
                        <span className="font-medium">
                          {result.auto_correlation.lag_1}
                        </span>
                        <span className="text-gray-500">
                          {' '}
                          &mdash; {result.auto_correlation.note}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

import { useState, useEffect, useRef, useCallback } from 'react'
import { apiClient } from '../../api/client'
import { HexViewer } from '../HexViewer/HexViewer'
import { Copy, Check, Search, Hash, Disc3, Play, X, Plus, GripVertical, ChevronDown, ChevronRight } from 'lucide-react'

type Tab = 'recipe' | 'hexview' | 'hashid' | 'charset'

const CODEC_GROUPS = [
  {
    label: 'Encoding',
    items: [
      { value: 'base64_encode', label: 'Base64 Encode' },
      { value: 'base64_decode', label: 'Base64 Decode' },
      { value: 'base64url_encode', label: 'Base64 URL Encode' },
      { value: 'base64url_decode', label: 'Base64 URL Decode' },
      { value: 'base32_encode', label: 'Base32 Encode' },
      { value: 'base32_decode', label: 'Base32 Decode' },
      { value: 'base85_encode', label: 'Base85 Encode' },
      { value: 'base85_decode', label: 'Base85 Decode' },
      { value: 'base91_encode', label: 'Base91 Encode' },
      { value: 'base91_decode', label: 'Base91 Decode' },
    ],
  },
  {
    label: 'URL',
    items: [
      { value: 'url_encode', label: 'URL Encode' },
      { value: 'url_decode', label: 'URL Decode' },
      { value: 'url_encode_all', label: 'URL Encode All' },
      { value: 'url_encode_double', label: 'URL Double Encode' },
      { value: 'smart_url_decode', label: 'URL Decode (Smart)' },
    ],
  },
  {
    label: 'String',
    items: [
      { value: 'hex_encode', label: 'Hex Encode' },
      { value: 'hex_decode', label: 'Hex Decode' },
      { value: 'html_encode', label: 'HTML Encode' },
      { value: 'html_decode', label: 'HTML Decode' },
      { value: 'unicode_escape', label: 'Unicode Escape' },
      { value: 'unicode_unescape', label: 'Unicode Unescape' },
      { value: 'binary_encode', label: 'Binary Encode' },
      { value: 'binary_decode', label: 'Binary Decode' },
      { value: 'octal_encode', label: 'Octal Encode' },
      { value: 'octal_decode', label: 'Octal Decode' },
      { value: 'punycode_encode', label: 'Punycode Encode' },
      { value: 'punycode_decode', label: 'Punycode Decode' },
    ],
  },
  {
    label: 'Compress',
    items: [
      { value: 'zlib_compress', label: 'Zlib Compress' },
      { value: 'zlib_decompress', label: 'Zlib Decompress' },
      { value: 'gzip', label: 'Gzip Compress' },
      { value: 'gunzip', label: 'Gzip Decompress' },
    ],
  },
  {
    label: 'Utility',
    items: [
      { value: 'rot13', label: 'ROT13' },
      { value: 'quoted_printable_encode', label: 'QP Encode' },
      { value: 'quoted_printable_decode', label: 'QP Decode' },
      { value: 'jwt_decode', label: 'JWT Decode' },
    ],
  },
  {
    label: 'Hashing',
    items: [
      { value: 'md5', label: 'MD5' },
      { value: 'sha1', label: 'SHA-1' },
      { value: 'sha224', label: 'SHA-224' },
      { value: 'sha256', label: 'SHA-256' },
      { value: 'sha384', label: 'SHA-384' },
      { value: 'sha512', label: 'SHA-512' },
    ],
  },
]

interface ChainStep {
  step: number
  codec: string
  input: string
  output: string
}

interface SmartResult {
  codec: string
  output: string
  confidence: number
}

interface HashResult {
  hash_type: string
  length: number
  bit_length: number | null
  is_hex: boolean
  confidence: string
}

interface CharsetResult {
  charset: string
  confidence: string
  method: string
}

export function Decoder() {
  const [activeTab, setActiveTab] = useState<Tab>('recipe')

  // Recipe State
  const [recipeInput, setRecipeInput] = useState('')
  const [recipeOutput, setRecipeOutput] = useState('')
  const [recipeSteps, setRecipeSteps] = useState<{ id: string; codec: string }[]>([])
  const [chainSteps, setChainSteps] = useState<ChainStep[]>([])
  const [recipeLoading, setRecipeLoading] = useState(false)
  const [recipeError, setRecipeError] = useState('')
  const [recipeCopied, setRecipeCopied] = useState(false)
  const [showChain, setShowChain] = useState(true)
  const [smartResults, setSmartResults] = useState<SmartResult[]>([])
  const [smartLoading, setSmartLoading] = useState(false)
  const [dragIdx, setDragIdx] = useState<number | null>(null)

  // Other tools state
  const [hashInput, setHashInput] = useState('')
  const [hashResults, setHashResults] = useState<HashResult[]>([])
  const [hashLoading, setHashLoading] = useState(false)

  const [charsetInput, setCharsetInput] = useState('')
  const [charsetResult, setCharsetResult] = useState<CharsetResult | null>(null)
  const [charsetLoading, setCharsetLoading] = useState(false)

  const [hexInput, setHexInput] = useState('')

  const inputRef = useRef<HTMLTextAreaElement>(null)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    if (recipeSteps.length === 0) {
      setRecipeOutput(recipeInput)
      setChainSteps([])
      return
    }
    if (!recipeInput) return
    debounceRef.current = setTimeout(() => {
      runRecipe()
    }, 500)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [recipeSteps, recipeInput])

  const runRecipe = useCallback(async () => {
    if (!recipeInput || recipeSteps.length === 0) return
    setRecipeError('')
    setRecipeLoading(true)
    try {
      const { data } = await apiClient.post('/api/decoder/recipe', {
        input: recipeInput,
        steps: recipeSteps.map(s => ({ codec: s.codec }))
      })
      setRecipeOutput(data.final_output)
      setChainSteps(data.chain || [])
    } catch (err: any) {
      setRecipeError(err.response?.data?.detail || err.message)
      setRecipeOutput('')
      setChainSteps([])
    } finally {
      setRecipeLoading(false)
    }
  }, [recipeInput, recipeSteps])

  const handleSmartDecode = async () => {
    if (!recipeInput) return
    setSmartLoading(true)
    setRecipeError('')
    try {
      const { data } = await apiClient.post('/api/decoder/smart-decode', { input: recipeInput })
      setSmartResults(data.results)
    } catch (err: any) {
      setRecipeError(err.response?.data?.detail || err.message)
    } finally {
      setSmartLoading(false)
    }
  }

  const addStep = (codec: string) => {
    setRecipeSteps([...recipeSteps, { id: crypto.randomUUID(), codec }])
  }

  const removeStep = (id: string) => {
    setRecipeSteps(recipeSteps.filter(s => s.id !== id))
  }

  const moveStep = (from: number, to: number) => {
    const steps = [...recipeSteps]
    const [moved] = steps.splice(from, 1)
    steps.splice(to, 0, moved)
    setRecipeSteps(steps)
  }

  const handleDragStart = (idx: number) => {
    setDragIdx(idx)
  }

  const handleDragOver = (e: React.DragEvent, idx: number) => {
    e.preventDefault()
    if (dragIdx === null || dragIdx === idx) return
    moveStep(dragIdx, idx)
    setDragIdx(idx)
  }

  const handleDragEnd = () => {
    setDragIdx(null)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault()
      runRecipe()
    }
  }

  const handleHashIdentify = async () => {
    if (!hashInput) return
    setHashLoading(true)
    try {
      const { data } = await apiClient.post('/api/decoder/hash-identify', { hash: hashInput })
      setHashResults(data.results)
    } catch (err: any) {} finally { setHashLoading(false) }
  }

  const handleCharsetDetect = async () => {
    if (!charsetInput) return
    setCharsetLoading(true)
    try {
      const { data } = await apiClient.post('/api/decoder/charset-detect', { data: charsetInput })
      setCharsetResult(data)
    } catch (err: any) {} finally { setCharsetLoading(false) }
  }

  const copyOutput = async () => {
    try {
      await navigator.clipboard.writeText(recipeOutput)
      setRecipeCopied(true)
      setTimeout(() => setRecipeCopied(false), 2000)
    } catch {}
  }

  const codecLabel = (value: string) => {
    for (const g of CODEC_GROUPS) {
      const found = g.items.find((i) => i.value === value)
      if (found) return found.label
    }
    return value
  }

  const confidenceBadge = (c: string) => {
    switch (c) {
      case 'high': return 'bg-green-900 text-green-300'
      case 'medium': return 'bg-yellow-900 text-yellow-300'
      case 'low': return 'bg-orange-900 text-orange-300'
      default: return 'bg-gray-800 text-gray-400'
    }
  }

  const renderStepIcon = (codec: string) => {
    if (codec.startsWith('base')) return <span className="text-blue-400 text-[10px] font-bold">B</span>
    if (codec.startsWith('url')) return <span className="text-cyan-400 text-[10px] font-bold">U</span>
    if (codec.startsWith('hex')) return <span className="text-green-400 text-[10px] font-bold">H</span>
    if (codec.startsWith('html')) return <span className="text-orange-400 text-[10px] font-bold">H</span>
    if (codec.startsWith('unicode')) return <span className="text-purple-400 text-[10px] font-bold">U</span>
    if (codec.startsWith('binary')) return <span className="text-yellow-400 text-[10px] font-bold">B</span>
    if (codec.startsWith('octal')) return <span className="text-pink-400 text-[10px] font-bold">O</span>
    if (codec.startsWith('zlib') || codec.startsWith('gzip')) return <span className="text-red-400 text-[10px] font-bold">Z</span>
    if (codec.startsWith('rot')) return <span className="text-teal-400 text-[10px] font-bold">R</span>
    if (codec.startsWith('jwt')) return <span className="text-indigo-400 text-[10px] font-bold">J</span>
    if (codec.startsWith('quoted')) return <span className="text-slate-400 text-[10px] font-bold">Q</span>
    if (codec.startsWith('punycode')) return <span className="text-lime-400 text-[10px] font-bold">P</span>
    if (codec.startsWith('base64url')) return <span className="text-blue-300 text-[10px] font-bold">B</span>
    if (codec.startsWith('md5') || codec.startsWith('sha')) return <span className="text-amber-400 text-[10px] font-bold">#</span>
    return <span className="text-gray-400 text-[10px] font-bold">?</span>
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300">
        Decoder Pipeline
      </div>

      <div className="flex border-b border-gray-800 text-xs shrink-0">
        {(
          [
            { key: 'recipe', label: 'Recipe' },
            { key: 'hexview', label: 'Hex Viewer' },
            { key: 'hashid', label: 'Hash ID' },
            { key: 'charset', label: 'Charset' },
          ] as { key: Tab; label: string }[]
        ).map((tab) => (
          <button
            key={tab.key}
            className={`px-3 py-2 border-b-2 transition-colors ${
              activeTab === tab.key ? 'border-purple-500 text-purple-400' : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-hidden">
        {activeTab === 'recipe' && (
          <div className="flex h-full">
            {/* Left Sidebar - Operations */}
            <div className="w-56 border-r border-gray-800 flex flex-col bg-gray-950">
              <div className="p-2.5 border-b border-gray-800 text-xs font-medium text-gray-400">
                Operations
              </div>
              <div className="flex-1 overflow-y-auto p-2 space-y-3">
                {CODEC_GROUPS.map(group => (
                  <div key={group.label}>
                    <div className="text-[10px] uppercase font-bold tracking-wider text-gray-600 mb-1.5 pl-1">{group.label}</div>
                    <div className="space-y-0.5">
                      {group.items.map(item => (
                        <button
                          key={item.value}
                          onClick={() => addStep(item.value)}
                          className="w-full text-left px-2 py-1 rounded text-xs text-gray-300 hover:bg-gray-800 hover:text-purple-400 flex items-center gap-2 group transition-colors"
                        >
                          <Plus size={11} className="opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                          <span className="truncate">{item.label}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Middle Column - Recipe */}
            <div className="w-72 border-r border-gray-800 flex flex-col bg-gray-900/50">
              <div className="p-2.5 border-b border-gray-800 flex items-center justify-between">
                <span className="text-xs font-medium text-gray-400">Recipe</span>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-gray-600">{recipeSteps.length} steps</span>
                  <button
                    onClick={() => setRecipeSteps([])}
                    className="text-[10px] text-red-400 hover:text-red-300 disabled:opacity-50"
                    disabled={recipeSteps.length === 0}
                  >
                    Clear
                  </button>
                </div>
              </div>
              <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
                {recipeSteps.length === 0 ? (
                  <div className="text-xs text-gray-600 text-center py-8 px-4 border border-dashed border-gray-700 rounded-lg mt-2">
                    Click operations on the left to build a pipeline.
                  </div>
                ) : (
                  recipeSteps.map((step, idx) => (
                    <div
                      key={step.id}
                      draggable
                      onDragStart={() => handleDragStart(idx)}
                      onDragOver={(e) => handleDragOver(e, idx)}
                      onDragEnd={handleDragEnd}
                      className={`bg-gray-800/80 border rounded p-2 flex items-center gap-2 group cursor-grab active:cursor-grabbing transition-all ${
                        dragIdx === idx ? 'border-purple-500 opacity-70' : 'border-gray-700'
                      }`}
                    >
                      <div className="text-gray-500 shrink-0">
                        <GripVertical size={13} />
                      </div>
                      <div className="w-5 h-5 rounded bg-gray-700 flex items-center justify-center shrink-0">
                        {renderStepIcon(step.codec)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-medium text-gray-200 truncate">
                          <span className="text-gray-500 mr-1">{idx + 1}.</span>
                          {codecLabel(step.codec)}
                        </div>
                      </div>
                      <button
                        onClick={() => removeStep(step.id)}
                        className="text-gray-600 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                      >
                        <X size={13} />
                      </button>
                    </div>
                  ))
                )}
                {recipeLoading && (
                  <div className="text-xs text-purple-400 text-center py-2 flex items-center justify-center gap-1.5">
                    <span className="w-1.5 h-1.5 bg-purple-400 rounded-full animate-bounce" />
                    <span className="w-1.5 h-1.5 bg-purple-400 rounded-full animate-bounce [animation-delay:0.1s]" />
                    <span className="w-1.5 h-1.5 bg-purple-400 rounded-full animate-bounce [animation-delay:0.2s]" />
                  </div>
                )}
              </div>
            </div>

            {/* Right Column - I/O */}
            <div className="flex-1 flex flex-col min-w-0">
              {/* Input Area */}
              <div className="flex-1 flex flex-col border-b border-gray-800 min-h-0">
                <div className="p-2 border-b border-gray-800 flex items-center justify-between bg-gray-900/50 shrink-0">
                  <span className="text-xs font-medium text-gray-400">Input</span>
                  <div className="flex items-center gap-2">
                    <button
                      className="bg-purple-600 hover:bg-purple-700 px-2.5 py-1 rounded text-[10px] font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
                      onClick={runRecipe}
                      disabled={recipeLoading || !recipeInput || recipeSteps.length === 0}
                    >
                      <Play size={11} />
                      Run (Ctrl+Enter)
                    </button>
                    <button
                      className="bg-emerald-700 hover:bg-emerald-800 px-2.5 py-1 rounded text-[10px] font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
                      onClick={handleSmartDecode}
                      disabled={smartLoading || !recipeInput}
                    >
                      {smartLoading ? <span className="animate-pulse">...</span> : <Search size={11} />}
                      Magic
                    </button>
                  </div>
                </div>
                <div className="flex-1 relative min-h-0">
                  <textarea
                    ref={inputRef}
                    className="absolute inset-0 w-full h-full bg-transparent p-3 text-xs font-mono text-gray-300 resize-none outline-none"
                    placeholder="Enter data here..."
                    value={recipeInput}
                    onChange={(e) => setRecipeInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                  />
                </div>
                {smartResults.length > 0 && (
                  <div className="bg-gray-900 border-t border-gray-800 p-2 max-h-36 overflow-y-auto shrink-0">
                    <div className="text-[10px] font-medium text-purple-400 mb-1.5 px-1">Magic Results — click to apply:</div>
                    <div className="space-y-1">
                      {smartResults.map((r, i) => (
                        <div
                          key={i}
                          className="flex items-center gap-2 bg-gray-800 rounded p-1.5 cursor-pointer hover:bg-gray-700"
                          onClick={() => {
                            setRecipeSteps([{ id: crypto.randomUUID(), codec: r.codec }])
                            setSmartResults([])
                          }}
                        >
                          <span className="text-xs font-medium text-purple-300 min-w-[120px]">{codecLabel(r.codec)}</span>
                          <span className={`text-[10px] font-mono ${r.confidence > 0.7 ? 'text-green-400' : 'text-yellow-400'}`}>
                            {Math.round(r.confidence * 100)}%
                          </span>
                          <span className="text-xs text-gray-400 truncate flex-1">{r.output}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Chain Intermediate Steps */}
              {chainSteps.length > 0 && (
                <div className="border-b border-gray-800 bg-gray-900/40 shrink-0">
                  <button
                    className="w-full flex items-center gap-1.5 px-3 py-1.5 text-[10px] text-gray-500 hover:text-gray-300"
                    onClick={() => setShowChain(!showChain)}
                  >
                    {showChain ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    Pipeline Steps ({chainSteps.length})
                  </button>
                  {showChain && (
                    <div className="px-3 pb-2 space-y-1.5 max-h-40 overflow-y-auto">
                      {chainSteps.map((step, i) => (
                        <div key={i} className="bg-gray-800/50 rounded p-2 border border-gray-700/50">
                          <div className="flex items-center gap-1.5 mb-1">
                            <span className="text-[10px] text-gray-500">#{step.step}</span>
                            <span className="text-[10px] font-medium text-purple-400">{codecLabel(step.codec)}</span>
                          </div>
                          <div className="text-[10px] font-mono text-gray-500 truncate">
                            <span className="text-gray-600">→ </span>
                            {step.output?.length > 120 ? step.output.slice(0, 120) + '...' : step.output}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Output Area */}
              <div className="flex-1 flex flex-col bg-gray-900/30 min-h-0">
                <div className="p-2 border-b border-gray-800 flex items-center justify-between bg-gray-900/50 shrink-0">
                  <span className="text-xs font-medium text-gray-400 flex items-center gap-2">
                    Output
                    {recipeError && <span className="text-red-400 text-[10px]">Error: {recipeError}</span>}
                  </span>
                  <button
                    className="text-[10px] text-gray-400 hover:text-gray-200 flex items-center gap-1 bg-gray-800 px-2 py-1 rounded"
                    onClick={copyOutput}
                    disabled={!recipeOutput}
                  >
                    {recipeCopied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                    {recipeCopied ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <div className="flex-1 relative min-h-0">
                  <textarea
                    className="absolute inset-0 w-full h-full bg-transparent p-3 text-xs font-mono text-emerald-400 resize-none outline-none"
                    value={recipeOutput}
                    readOnly
                    placeholder="Result will appear here..."
                  />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Hex Viewer Tab */}
        {activeTab === 'hexview' && (
          <div className="h-full flex flex-col p-4 space-y-2">
            <textarea
              className="w-full h-24 shrink-0 bg-gray-900 border border-gray-800 rounded p-2 text-xs font-mono text-gray-300 resize-none outline-none focus:border-purple-700"
              placeholder="Input data for hex dump..."
              value={hexInput}
              onChange={(e) => setHexInput(e.target.value)}
            />
            <div className="flex-1 bg-gray-900 border border-gray-800 rounded p-2 overflow-auto">
              {hexInput ? <HexViewer data={hexInput} /> : <div className="text-xs text-gray-600 text-center py-8">Enter data above to view hex dump</div>}
            </div>
          </div>
        )}

        {/* Hash ID Tab */}
        {activeTab === 'hashid' && (
          <div className="p-4 space-y-4">
            <div className="flex gap-2">
              <input
                className="flex-1 bg-gray-900 border border-gray-800 rounded px-3 py-2 text-xs font-mono text-gray-300 outline-none focus:border-purple-700"
                placeholder="Paste a hash value..."
                value={hashInput}
                onChange={(e) => setHashInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleHashIdentify()}
              />
              <button
                className="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded text-xs font-medium flex items-center gap-2"
                onClick={handleHashIdentify}
                disabled={hashLoading}
              >
                <Hash size={14} /> {hashLoading ? '...' : 'Identify'}
              </button>
            </div>
            {hashResults.length > 0 && (
              <div className="space-y-2">
                {hashResults.map((r, i) => (
                  <div key={i} className="bg-gray-900 border border-gray-800 rounded p-3 flex items-center justify-between">
                    <div>
                      <div className="text-sm font-medium text-purple-400">{r.hash_type}</div>
                      <div className="text-xs text-gray-500 mt-1">Length: {r.length} | {r.is_hex ? 'Hex' : 'Non-hex'}</div>
                    </div>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${confidenceBadge(r.confidence)}`}>{r.confidence}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Charset Tab */}
        {activeTab === 'charset' && (
          <div className="p-4 space-y-4">
            <textarea
              className="w-full h-32 bg-gray-900 border border-gray-800 rounded p-3 text-xs font-mono text-gray-300 resize-none outline-none focus:border-purple-700"
              placeholder="Paste data to detect charset..."
              value={charsetInput}
              onChange={(e) => setCharsetInput(e.target.value)}
            />
            <button
              className="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded text-xs font-medium flex items-center gap-2"
              onClick={handleCharsetDetect}
              disabled={charsetLoading}
            >
              <Disc3 size={14} /> Detect Charset
            </button>
            {charsetResult && (
              <div className="bg-gray-900 border border-gray-800 rounded p-4 flex items-center justify-between">
                <div>
                  <div className="text-sm font-medium text-purple-400">{charsetResult.charset}</div>
                  <div className="text-xs text-gray-500 mt-1">Method: {charsetResult.method}</div>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded-full ${confidenceBadge(charsetResult.confidence)}`}>{charsetResult.confidence}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

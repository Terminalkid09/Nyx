import { useState } from 'react'
import { Key, Shield, Unlock, Bug } from 'lucide-react'
import { decodeJwt, analyzeJwt, bruteJwt, crackJwt, debugOAuth } from '../../api/endpoints/auth'
import { AuthJwtResult } from '../../types'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10',
  high: 'text-orange-400 bg-orange-400/10',
  medium: 'text-yellow-400 bg-yellow-400/10',
  low: 'text-green-400 bg-green-400/10',
  info: 'text-gray-400 bg-gray-400/10',
}

type Tab = 'decode' | 'analyze' | 'crack' | 'oauth'

export function AuthTester() {
  const [activeTab, setActiveTab] = useState<Tab>('decode')
  const [jwtToken, setJwtToken] = useState('')
  const [crackSecret, setCrackSecret] = useState('')
  const [oauthParams, setOauthParams] = useState<Record<string, string>>({
    client_id: '',
    redirect_uri: '',
    response_type: '',
    scope: '',
    state: '',
    nonce: '',
  })
  const [decoded, setDecoded] = useState<AuthJwtResult | null>(null)
  const [analysis, setAnalysis] = useState<{ issues: { type: string; severity: string; description: string }[] } | null>(null)
  const [bruteResult, setBruteResult] = useState<{ found: boolean; secret?: string; attempts: number } | null>(null)
  const [crackResult, setCrackResult] = useState<{ valid: boolean } | null>(null)
  const [oauthResult, setOauthResult] = useState<{ issues: string[] } | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleDecode = async () => {
    if (!jwtToken.trim()) return
    setLoading(true)
    setError('')
    setDecoded(null)
    try {
      const result = await decodeJwt(jwtToken.trim())
      setDecoded(result)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleAnalyze = async () => {
    if (!jwtToken.trim()) return
    setLoading(true)
    setError('')
    setAnalysis(null)
    try {
      const result = await analyzeJwt(jwtToken.trim())
      setAnalysis(result)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleBrute = async () => {
    if (!jwtToken.trim()) return
    setLoading(true)
    setError('')
    setBruteResult(null)
    try {
      const result = await bruteJwt(jwtToken.trim())
      setBruteResult(result)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleCrack = async () => {
    if (!jwtToken.trim() || !crackSecret.trim()) return
    setLoading(true)
    setError('')
    setCrackResult(null)
    try {
      const result = await crackJwt(jwtToken.trim(), crackSecret.trim())
      setCrackResult(result)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleOAuthDebug = async () => {
    const filled = Object.entries(oauthParams).filter(([, v]) => v.trim())
    if (filled.length === 0) return
    setLoading(true)
    setError('')
    setOauthResult(null)
    try {
      const params: Record<string, string> = {}
      for (const [k, v] of filled) params[k] = v.trim()
      const result = await debugOAuth(params)
      setOauthResult(result)
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }

  const tabs: { id: Tab; label: string; icon: typeof Key }[] = [
    { id: 'decode', label: 'JWT Decode', icon: Key },
    { id: 'analyze', label: 'JWT Analyze', icon: Shield },
    { id: 'crack', label: 'JWT Crack', icon: Unlock },
    { id: 'oauth', label: 'OAuth Debug', icon: Bug },
  ]

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-gray-800 text-sm font-medium text-gray-300 flex items-center gap-2">
        <Key size={16} />
        <span>Auth Tester</span>
      </div>
      <div className="flex border-b border-gray-800">
        {tabs.map((tab) => {
          const Icon = tab.icon
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1 px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-purple-500 text-purple-400'
                  : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}
            >
              <Icon size={14} />
              {tab.label}
            </button>
          )
        })}
      </div>
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {error && <div className="text-xs text-red-400 bg-red-400/10 rounded p-2">{error}</div>}

        {activeTab === 'decode' && (
          <>
            <div>
              <label className="text-xs text-gray-500 block mb-1">JWT Token</label>
              <textarea
                className="w-full h-24 bg-gray-900 border border-gray-800 rounded p-2 text-xs font-mono text-gray-300 resize-none"
                value={jwtToken}
                onChange={(e) => setJwtToken(e.target.value)}
                placeholder="eyJhbGciOiJIUzI1NiIs..."
              />
            </div>
            <button
              onClick={handleDecode}
              className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium disabled:opacity-50 flex items-center gap-1"
              disabled={loading || !jwtToken.trim()}
            >
              <Key size={14} /> {loading ? 'Decoding...' : 'Decode'}
            </button>
            {decoded && (
              <div className="space-y-3">
                <div>
                  <div className="text-xs font-medium text-gray-400 mb-1">Header</div>
                  <pre className="bg-gray-950 border border-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-x-auto">{JSON.stringify(decoded.header, null, 2)}</pre>
                </div>
                <div>
                  <div className="text-xs font-medium text-gray-400 mb-1">Payload</div>
                  <pre className="bg-gray-950 border border-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-x-auto">{JSON.stringify(decoded.payload, null, 2)}</pre>
                </div>
                <div>
                  <div className="text-xs font-medium text-gray-400 mb-1">Signature</div>
                  <div className="bg-gray-950 border border-gray-800 rounded p-2 text-xs font-mono text-gray-500 break-all">{decoded.signature}</div>
                </div>
              </div>
            )}
          </>
        )}

        {activeTab === 'analyze' && (
          <>
            <div>
              <label className="text-xs text-gray-500 block mb-1">JWT Token</label>
              <textarea
                className="w-full h-24 bg-gray-900 border border-gray-800 rounded p-2 text-xs font-mono text-gray-300 resize-none"
                value={jwtToken}
                onChange={(e) => setJwtToken(e.target.value)}
                placeholder="eyJhbGciOiJIUzI1NiIs..."
              />
            </div>
            <button
              onClick={handleAnalyze}
              className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium disabled:opacity-50 flex items-center gap-1"
              disabled={loading || !jwtToken.trim()}
            >
              <Shield size={14} /> {loading ? 'Analyzing...' : 'Analyze'}
            </button>
            {analysis && (
              <div className="space-y-2">
                {analysis.issues.length === 0 ? (
                  <div className="text-xs text-green-400">No issues found.</div>
                ) : (
                  (analysis?.issues || []).map((issue, i) => (
                    <div key={i} className="bg-gray-900 border border-gray-800 rounded p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${SEVERITY_COLORS[issue.severity] || ''}`}>
                          {issue.severity.toUpperCase()}
                        </span>
                        <span className="text-xs font-medium text-gray-300">{issue.type}</span>
                      </div>
                      <div className="text-xs text-gray-400">{issue.description}</div>
                    </div>
                  ))
                )}
              </div>
            )}
          </>
        )}

        {activeTab === 'crack' && (
          <>
            <div>
              <label className="text-xs text-gray-500 block mb-1">JWT Token</label>
              <textarea
                className="w-full h-24 bg-gray-900 border border-gray-800 rounded p-2 text-xs font-mono text-gray-300 resize-none"
                value={jwtToken}
                onChange={(e) => setJwtToken(e.target.value)}
                placeholder="eyJhbGciOiJIUzI1NiIs..."
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">Brute Force (common secrets)</label>
              <button
                onClick={handleBrute}
                className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium disabled:opacity-50 flex items-center gap-1"
                disabled={loading || !jwtToken.trim()}
              >
                <Unlock size={14} /> {loading ? 'Bruting...' : 'Brute Force'}
              </button>
              {bruteResult && (
                <div className="mt-2 bg-gray-900 border border-gray-800 rounded p-3 text-xs space-y-1">
                  {bruteResult.found ? (
                    <div className="text-green-400 font-medium">Secret found: {bruteResult.secret}</div>
                  ) : (
                    <div className="text-red-400 font-medium">Secret not found</div>
                  )}
                  <div className="text-gray-400">Attempts: {bruteResult.attempts}</div>
                </div>
              )}
            </div>
            <div className="border-t border-gray-800 pt-3">
              <div className="text-xs font-medium text-gray-400 mb-2">Verify with Known Secret</div>
              <div className="flex gap-2 items-end">
                <div className="flex-1">
                  <label className="text-xs text-gray-500 block mb-1">Secret</label>
                  <input
                    className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                    value={crackSecret}
                    onChange={(e) => setCrackSecret(e.target.value)}
                    placeholder="secret key"
                  />
                </div>
                <button
                  onClick={handleCrack}
                  className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium disabled:opacity-50 flex items-center gap-1"
                  disabled={loading || !jwtToken.trim() || !crackSecret.trim()}
                >
                  <Unlock size={14} /> Verify
                </button>
              </div>
              {crackResult && (
                <div className="mt-2 text-xs">
                  {crackResult.valid ? (
                    <span className="text-green-400">Signature is VALID</span>
                  ) : (
                    <span className="text-red-400">Signature is INVALID</span>
                  )}
                </div>
              )}
            </div>
          </>
        )}

        {activeTab === 'oauth' && (
          <>
            <div className="grid grid-cols-2 gap-3">
              {Object.keys(oauthParams).map((key) => (
                <div key={key}>
                  <label className="text-xs text-gray-500 block mb-1">{key}</label>
                  <input
                    className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
                    value={oauthParams[key]}
                    onChange={(e) => setOauthParams({ ...oauthParams, [key]: e.target.value })}
                    placeholder={key}
                  />
                </div>
              ))}
            </div>
            <button
              onClick={handleOAuthDebug}
              className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-xs font-medium disabled:opacity-50 flex items-center gap-1"
              disabled={loading}
            >
              <Bug size={14} /> {loading ? 'Debugging...' : 'Debug OAuth'}
            </button>
            {oauthResult && (
              <div className="space-y-2">
                {oauthResult.issues.length === 0 ? (
                  <div className="text-xs text-green-400">No issues detected.</div>
                ) : (
                  (oauthResult?.issues || []).map((issue, i) => (
                    <div key={i} className="bg-gray-900 border border-gray-800 rounded p-2 text-xs text-gray-300">
                      {issue}
                    </div>
                  ))
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

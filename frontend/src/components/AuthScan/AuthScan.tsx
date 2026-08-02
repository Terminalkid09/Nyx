import { useState, useEffect } from 'react'
import { Key, Plus, Trash2, Shield, Play } from 'lucide-react'
import { listAuthProfiles, createAuthProfile, deleteAuthProfile, runAuthScan, AuthProfile } from '../../api/endpoints/authScan'

export function AuthScan() {
  const [profiles, setProfiles] = useState<AuthProfile[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [name, setName] = useState('')
  const [loginUrl, setLoginUrl] = useState('')
  const [checkUrl, setCheckUrl] = useState('')
  const [checkPattern, setCheckPattern] = useState('')
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState<any>(null)

  useEffect(() => { listAuthProfiles().then(setProfiles).catch(() => {}).finally(() => setLoading(false)) }, [])

  const handleCreate = async () => {
    if (!name) return
    const p = await createAuthProfile({ name, login_url: loginUrl, check_url: checkUrl, check_pattern: checkPattern, steps: [], headers: {} })
    setProfiles([...profiles, p]); setShowForm(false); setName(''); setLoginUrl(''); setCheckUrl(''); setCheckPattern('')
  }

  const handleDelete = async (id: string) => {
    await deleteAuthProfile(id); setProfiles(profiles.filter(p => p.id !== id))
  }

  const handleScan = async (profileId: string, targetUrl: string) => {
    setScanning(true); setScanResult(null)
    try { setScanResult(await runAuthScan(profileId, targetUrl)) } catch (e: any) { setScanResult({ error: e?.response?.data?.detail || 'Scan failed' }) }
    finally { setScanning(false) }
  }

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Key className="w-6 h-6 text-purple-400" />
        <h1 className="text-xl font-bold text-gray-100">Auth Scan</h1>
      </div>

      <div className="flex justify-end">
        <button onClick={() => setShowForm(!showForm)} className="bg-purple-600 hover:bg-purple-700 px-3 py-1.5 rounded text-xs font-medium text-white flex items-center gap-1.5 transition-colors"><Plus className="w-3.5 h-3.5" /> New Profile</button>
      </div>

      {showForm && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <input className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" value={name} onChange={e => setName(e.target.value)} placeholder="Profile name" />
            <input className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" value={loginUrl} onChange={e => setLoginUrl(e.target.value)} placeholder="Login URL" />
            <input className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" value={checkUrl} onChange={e => setCheckUrl(e.target.value)} placeholder="Auth check URL" />
            <input className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono" value={checkPattern} onChange={e => setCheckPattern(e.target.value)} placeholder="Check pattern (regex)" />
          </div>
          <button onClick={handleCreate} className="bg-purple-600 hover:bg-purple-700 px-4 py-1.5 rounded text-xs font-medium text-white transition-colors">Create Profile</button>
        </div>
      )}

      {loading ? (
        <div className="text-center py-12 text-gray-500">Loading...</div>
      ) : profiles.length === 0 ? (
        <div className="text-center py-12 text-gray-500">No auth profiles. Create one to start authenticated scanning.</div>
      ) : (
        <div className="space-y-3">
          {profiles.map(p => (
            <div key={p.id} className="bg-gray-900 border border-gray-800 rounded-lg px-5 py-3">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-sm font-medium text-gray-200">{p.name}</span>
                  <p className="text-xs text-gray-500 mt-0.5">Login: {p.login_url}</p>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => handleScan(p.id!, p.check_url)} disabled={scanning} className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-purple-400 transition-colors" title="Run auth scan"><Shield className="w-4 h-4" /></button>
                  <button onClick={() => handleDelete(p.id!)} className="p-1.5 rounded hover:bg-gray-800 text-gray-500 hover:text-red-400 transition-colors"><Trash2 className="w-4 h-4" /></button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {scanResult && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-3">
          <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2"><Shield className="w-4 h-4 text-purple-400" /> Scan Result</h3>
          {scanResult.error ? (
            <p className="text-sm text-red-400">{scanResult.error}</p>
          ) : (
            <>
              <p className="text-xs text-gray-400">Findings: <span className="text-gray-200 font-medium">{scanResult.findings_count}</span></p>
              {scanResult.exploits?.length > 0 && (
                <div className="space-y-2">
                  {scanResult.exploits.map((e: any, i: number) => (
                    <div key={i} className="bg-gray-800/50 rounded p-3">
                      <p className="text-xs text-gray-300 font-medium">{e.vulnerability}</p>
                      <pre className="text-xs text-gray-500 font-mono mt-1 whitespace-pre-wrap">{e.code}</pre>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}

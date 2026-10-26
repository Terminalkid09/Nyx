import { useEffect, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Pencil,
  Plus,
  Power,
  PowerOff,
  ScrollText,
  ShieldAlert,
  Trash2,
  X,
} from 'lucide-react'
import {
  createRoEProfile,
  deleteRoEProfile,
  listRoEProfiles,
  setRoEProfileActive,
  updateRoEProfile,
  type RoEInput,
  type RoEProfile,
} from '../../api/endpoints/roe'
import { useToast } from '../Toast'

function splitLines(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean)
}

function toIso(value: string): string | null {
  if (!value) return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date.toISOString()
}

function toLocalInput(value: string | null): string {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  const pad = (part: number) => String(part).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`
}

function formatWindow(profile: RoEProfile): string {
  if (!profile.window_start && !profile.window_end) return 'Always'
  const start = profile.window_start ? new Date(profile.window_start).toLocaleString() : 'now'
  const end = profile.window_end ? new Date(profile.window_end).toLocaleString() : 'no end'
  return `${start} → ${end}`
}

function errorText(error: any): string {
  const detail = error?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail.map((item) => item?.msg || JSON.stringify(item)).join('; ')
  }
  return error?.message || 'Unexpected error'
}

const EMPTY_PROFILE: RoEProfile | null = null

export function RulesOfEngagement() {
  const [profiles, setProfiles] = useState<RoEProfile[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [editing, setEditing] = useState<RoEProfile | null>(EMPTY_PROFILE)
  const [saving, setSaving] = useState(false)
  const [busyId, setBusyId] = useState<string | null>(null)

  const [name, setName] = useState('')
  const [targets, setTargets] = useState('')
  const [exclusions, setExclusions] = useState('')
  const [windowStart, setWindowStart] = useState('')
  const [windowEnd, setWindowEnd] = useState('')
  const [maxRps, setMaxRps] = useState('0')

  const { addToast } = useToast()

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      setProfiles(await listRoEProfiles())
    } catch (e: any) {
      setError(errorText(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const resetForm = () => {
    setEditing(null)
    setName('')
    setTargets('')
    setExclusions('')
    setWindowStart('')
    setWindowEnd('')
    setMaxRps('0')
  }

  const closeForm = () => {
    setShowForm(false)
    resetForm()
  }

  const openCreate = () => {
    resetForm()
    setShowForm(true)
  }

  const openEdit = (profile: RoEProfile) => {
    setEditing(profile)
    setName(profile.name)
    setTargets(profile.targets.join('\n'))
    setExclusions(profile.exclusions.join('\n'))
    setWindowStart(toLocalInput(profile.window_start))
    setWindowEnd(toLocalInput(profile.window_end))
    setMaxRps(String(profile.max_rps ?? 0))
    setShowForm(true)
  }

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    const input: RoEInput = {
      name: name.trim(),
      targets: splitLines(targets),
      exclusions: splitLines(exclusions),
      window_start: toIso(windowStart),
      window_end: toIso(windowEnd),
      max_rps: Number(maxRps) || 0,
    }
    if (!input.name) {
      addToast('error', 'Profile name is required')
      return
    }
    if (input.targets.length === 0) {
      addToast('error', 'Add at least one target host or pattern')
      return
    }
    if (input.window_start && input.window_end && input.window_end < input.window_start) {
      addToast('error', 'The end of the engagement window precedes its start')
      return
    }

    setSaving(true)
    try {
      if (editing) {
        await updateRoEProfile(editing.id, input)
        addToast('success', `Profile "${input.name}" updated and re-signed`)
      } else {
        await createRoEProfile(input)
        addToast('success', `Profile "${input.name}" created and signed`)
      }
      closeForm()
      await load()
    } catch (e: any) {
      addToast('error', errorText(e))
    } finally {
      setSaving(false)
    }
  }

  const toggleActive = async (profile: RoEProfile) => {
    setBusyId(profile.id)
    try {
      await setRoEProfileActive(profile.id, !profile.active)
      await load()
      addToast(
        'success',
        `Profile "${profile.name}" ${profile.active ? 'deactivated' : 'activated'}`,
      )
    } catch (e: any) {
      addToast('error', errorText(e))
    } finally {
      setBusyId(null)
    }
  }

  const remove = async (profile: RoEProfile) => {
    if (!window.confirm(`Delete the engagement profile "${profile.name}"?`)) return
    setBusyId(profile.id)
    try {
      await deleteRoEProfile(profile.id)
      await load()
      addToast('success', `Profile "${profile.name}" deleted`)
    } catch (e: any) {
      addToast('error', errorText(e))
    } finally {
      setBusyId(null)
    }
  }

  const activeCount = profiles.filter((profile) => profile.active && profile.signature_valid).length
  const invalidCount = profiles.filter((profile) => !profile.signature_valid).length

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6 overflow-y-auto h-full">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <ScrollText className="w-6 h-6 text-purple-400" />
          <div>
            <h1 className="text-xl font-bold text-gray-100">Rules of Engagement</h1>
            <p className="text-xs text-gray-500 mt-0.5">
              Signed authorization profiles enforced by every active probe.
            </p>
          </div>
        </div>
        <button
          onClick={openCreate}
          className="bg-purple-600 hover:bg-purple-700 px-3 py-1.5 rounded text-xs font-medium text-white flex items-center gap-1.5 transition-colors"
        >
          <Plus className="w-3.5 h-3.5" /> New Profile
        </button>
      </div>

      <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-4 text-xs text-gray-400 leading-relaxed">
        A profile authorizes active probing only for its target patterns, outside its exclusions
        and inside its time window. Profiles are signed with the local Nyx secret: changing the
        targets, exclusions, window or rate limit directly in the database invalidates the
        signature and the profile is ignored. Activation is a separate, reversible switch.
      </div>

      {invalidCount > 0 && (
        <div className="flex items-start gap-2 rounded-lg border border-red-900/50 bg-red-950/20 p-3 text-xs text-red-300">
          <ShieldAlert size={15} className="mt-0.5 shrink-0" />
          <span>
            {invalidCount} profile{invalidCount === 1 ? ' has' : 's have'} an invalid signature and
            {invalidCount === 1 ? ' is' : ' are'} ignored by the authorization gate. Re-create or
            re-save the profile to sign it again.
          </span>
        </div>
      )}

      {!loading && profiles.length > 0 && activeCount === 0 && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-900/50 bg-amber-950/20 p-3 text-xs text-amber-300">
          <AlertTriangle size={15} className="mt-0.5 shrink-0" />
          <span>
            No active RoE profile: active probing is not constrained by RoE. Create an active
            profile before testing a real engagement.
          </span>
        </div>
      )}

      {!loading && profiles.length > 0 && activeCount > 0 && (
        <div className="flex items-start gap-2 rounded-lg border border-green-900/40 bg-green-950/20 p-3 text-xs text-green-300">
          <CheckCircle2 size={15} className="mt-0.5 shrink-0" />
          <span>
            {activeCount} active profile{activeCount === 1 ? '' : 's'} enforcing scope and signed
            rate limits on every active probe.
          </span>
        </div>
      )}

      {showForm && (
        <form
          onSubmit={submit}
          className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-4"
        >
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-200">
              {editing ? `Edit "${editing.name}"` : 'New engagement profile'}
            </h2>
            <button
              type="button"
              onClick={closeForm}
              className="p-1 rounded hover:bg-gray-800 text-gray-500 hover:text-gray-300"
              aria-label="Close form"
            >
              <X size={14} />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <label className="space-y-1 md:col-span-2">
              <span className="text-xs text-gray-400">Name</span>
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="ACME Q4 external engagement"
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600"
              />
            </label>

            <label className="space-y-1">
              <span className="text-xs text-gray-400">Targets — one per line</span>
              <textarea
                value={targets}
                onChange={(event) => setTargets(event.target.value)}
                rows={4}
                placeholder={'*.acme.test\napi.acme.test'}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono placeholder:text-gray-600"
              />
              <span className="block text-[10px] text-gray-600">
                Host glob or URL prefix, e.g. <code>*.acme.test</code> or <code>https://api.acme.test/v1</code>.
              </span>
            </label>

            <label className="space-y-1">
              <span className="text-xs text-gray-400">Exclusions — one per line</span>
              <textarea
                value={exclusions}
                onChange={(event) => setExclusions(event.target.value)}
                rows={4}
                placeholder={'admin.acme.test\n*.acme.test/payments'}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono placeholder:text-gray-600"
              />
              <span className="block text-[10px] text-gray-600">
                Exclusions win over targets. Payment, admin and third-party paths belong here.
              </span>
            </label>

            <label className="space-y-1">
              <span className="text-xs text-gray-400">Window start</span>
              <input
                type="datetime-local"
                value={windowStart}
                onChange={(event) => setWindowStart(event.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200"
              />
            </label>

            <label className="space-y-1">
              <span className="text-xs text-gray-400">Window end</span>
              <input
                type="datetime-local"
                value={windowEnd}
                onChange={(event) => setWindowEnd(event.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200"
              />
            </label>

            <label className="space-y-1">
              <span className="text-xs text-gray-400">Rate limit (requests/second)</span>
              <input
                type="number"
                min={0}
                step="0.1"
                value={maxRps}
                onChange={(event) => setMaxRps(event.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200"
              />
              <span className="block text-[10px] text-gray-600">
                0 means no RoE-imposed rate limit.
              </span>
            </label>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="submit"
              disabled={saving}
              className="bg-purple-600 hover:bg-purple-700 disabled:opacity-50 px-4 py-1.5 rounded text-xs font-medium text-white transition-colors"
            >
              {saving ? 'Saving…' : editing ? 'Save and re-sign' : 'Create and sign'}
            </button>
            <button
              type="button"
              onClick={closeForm}
              className="px-4 py-1.5 rounded text-xs font-medium text-gray-400 hover:text-gray-200 hover:bg-gray-800 transition-colors"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {error && (
        <div className="text-xs text-red-400 bg-red-400/10 rounded p-3">{error}</div>
      )}

      {loading ? (
        <div className="text-center py-12 text-gray-500 text-sm">Loading profiles…</div>
      ) : profiles.length === 0 ? (
        <div className="text-center py-12 border border-dashed border-gray-800 rounded-lg">
          <ScrollText className="w-8 h-8 text-gray-700 mx-auto mb-2" />
          <p className="text-sm text-gray-400">No engagement profiles yet.</p>
          <p className="text-xs text-gray-600 mt-1">
            Without an active profile, active probing is unrestricted.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {profiles.map((profile) => (
            <div key={profile.id} className="bg-gray-900 border border-gray-800 rounded-lg">
              <div className="px-4 py-3 flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium text-gray-200">{profile.name}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded-full border ${
                    profile.active
                      ? 'bg-green-400/10 text-green-400 border-green-800/50'
                      : 'bg-gray-800 text-gray-500 border-gray-700'
                  }`}
                >
                  {profile.active ? 'ACTIVE' : 'INACTIVE'}
                </span>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded-full border ${
                    profile.signature_valid
                      ? 'bg-purple-400/10 text-purple-300 border-purple-800/50'
                      : 'bg-red-400/10 text-red-300 border-red-800/50'
                  }`}
                  title={profile.signature}
                >
                  {profile.signature_valid ? 'SIGNATURE VALID' : 'SIGNATURE INVALID'}
                </span>

                <div className="ml-auto flex items-center gap-1">
                  <button
                    onClick={() => toggleActive(profile)}
                    disabled={busyId === profile.id}
                    className="p-1.5 rounded hover:bg-gray-800 text-gray-500 hover:text-gray-200 disabled:opacity-40"
                    title={profile.active ? 'Deactivate' : 'Activate'}
                  >
                    {profile.active ? <PowerOff size={14} /> : <Power size={14} />}
                  </button>
                  <button
                    onClick={() => openEdit(profile)}
                    className="p-1.5 rounded hover:bg-gray-800 text-gray-500 hover:text-gray-200"
                    title="Edit"
                  >
                    <Pencil size={14} />
                  </button>
                  <button
                    onClick={() => remove(profile)}
                    disabled={busyId === profile.id}
                    className="p-1.5 rounded hover:bg-gray-800 text-gray-500 hover:text-red-400 disabled:opacity-40"
                    title="Delete"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>

              <div className="px-4 pb-4 grid grid-cols-1 md:grid-cols-3 gap-3 border-t border-gray-800 pt-3">
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-gray-600 mb-1">Targets</div>
                  <div className="flex flex-wrap gap-1">
                    {profile.targets.map((target) => (
                      <span
                        key={target}
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-400/10 text-purple-300"
                      >
                        {target}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-gray-600 mb-1">Exclusions</div>
                  <div className="flex flex-wrap gap-1">
                    {profile.exclusions.length === 0 ? (
                      <span className="text-[10px] text-gray-600">None</span>
                    ) : (
                      profile.exclusions.map((exclusion) => (
                        <span
                          key={exclusion}
                          className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-400/10 text-red-300"
                        >
                          {exclusion}
                        </span>
                      ))
                    )}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-gray-600 mb-1">Constraints</div>
                  <div className="text-[11px] text-gray-400 space-y-0.5">
                    <div>{formatWindow(profile)}</div>
                    <div>
                      {profile.max_rps > 0
                        ? `${profile.max_rps} req/s`
                        : 'No rate limit'}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

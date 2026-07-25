import { useState, useEffect } from 'react'
import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Shield, Repeat, Search, Zap, Replace, PauseCircle, GitCompare, FileSearch, Key, Globe, Users, FolderOpen, Play, Activity, Compass, Radio, BookOpen, Search as SearchIcon, Monitor, Wifi, ChevronDown, Plus } from 'lucide-react'
import { useSessionStore } from '../../store/useSessionStore'

const navGroups = [
  {
    name: 'GENERAL',
    items: [
      { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
      { to: '/projects', label: 'Projects', icon: FolderOpen },
      { to: '/organizer', label: 'Organizer', icon: BookOpen },
    ]
  },
  {
    name: 'TRAFFIC',
    items: [
      { to: '/proxy', label: 'Proxy', icon: Shield },
      { to: '/mitm', label: 'MITM', icon: Wifi },
      { to: '/interceptor', label: 'Interceptor', icon: PauseCircle },
      { to: '/repeater', label: 'Repeater', icon: Repeat },
      { to: '/match-replace', label: 'M&R Rules', icon: Replace },
      { to: '/websocket', label: 'WebSockets', icon: Globe },
    ]
  },
  {
    name: 'SCANNING & AUTOMATION',
    items: [
      { to: '/scanner', label: 'Scanner', icon: Search },
      { to: '/fuzzer', label: 'Fuzzer', icon: Zap },
      { to: '/content-discovery', label: 'Discovery', icon: Compass },
      { to: '/automation', label: 'AutoScan & Alerts', icon: Activity },
      { to: '/live-audit', label: 'Live Audit', icon: Radio },
    ]
  },
  {
    name: 'ADVANCED TOOLS',
    items: [
      { to: '/comparer', label: 'Comparer', icon: GitCompare },
      { to: '/inspector', label: 'Inspector', icon: SearchIcon },
      { to: '/search', label: 'Search', icon: FileSearch },
    ]
  },
  {
    name: 'SETTINGS',
    items: [
      { to: '/proxy-config', label: 'Proxy Config', icon: Monitor },
      { to: '/auth', label: 'Authentication', icon: Key },
      { to: '/session', label: 'Session Handling', icon: Users },
      { to: '/scan-jobs', label: 'Scan Jobs', icon: Play },
    ]
  }
]

function SessionSwitcher() {
  const { sessions, activeSessionId, fetchSessions, setActiveSession, createSession } = useSessionStore()
  const [creating, setCreating] = useState(false)
  const [newName, setNewName] = useState('')

  useEffect(() => { fetchSessions() }, [])

  const activeSession = sessions.find(s => s.id === activeSessionId)

  const handleCreate = async () => {
    if (!newName.trim()) return
    const s = await createSession(newName.trim())
    setActiveSession(s.id)
    setNewName('')
    setCreating(false)
  }

  return (
    <div className="px-3 pt-3 border-t border-gray-800">
      <span className="px-1 text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2 block">Active Session</span>
      <select
        className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-200 mb-1"
        value={activeSessionId}
        onChange={(e) => setActiveSession(e.target.value)}
      >
        {sessions.length === 0 && <option value="00000000-0000-0000-0000-000000000001">Default Session</option>}
        {sessions.map(s => (
          <option key={s.id} value={s.id}>{s.name}</option>
        ))}
      </select>
      {creating ? (
        <div className="flex gap-1">
          <input
            className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 placeholder:text-gray-600"
            placeholder="Session name..."
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
            autoFocus
          />
          <button onClick={handleCreate} className="bg-purple-600 hover:bg-purple-700 px-2 py-1 rounded text-xs text-white">✓</button>
          <button onClick={() => setCreating(false)} className="bg-gray-700 px-2 py-1 rounded text-xs text-gray-400">✕</button>
        </div>
      ) : (
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-1 text-[10px] text-purple-400 hover:text-purple-300 transition-colors"
        >
          <Plus size={11} /> New Session
        </button>
      )}
    </div>
  )
}

export function Sidebar() {
  return (
    <aside className="w-60 bg-gray-900 border-r border-gray-800 flex flex-col py-4 overflow-y-auto no-scrollbar">
      <div className="flex items-center gap-3 px-6 mb-6">
        <div className="w-8 h-8 rounded bg-gradient-to-br from-purple-600 to-indigo-600 flex items-center justify-center font-bold text-white text-lg shadow-[0_0_15px_rgba(147,51,234,0.5)]">
          N
        </div>
        <span className="font-bold text-xl tracking-wide text-gray-100">Nyx</span>
      </div>
      
      <div className="flex flex-col gap-6 px-3 flex-1">
        {navGroups.map((group) => (
          <div key={group.name} className="flex flex-col gap-1 w-full">
            <span className="px-3 text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-1">
              {group.name}
            </span>
            {group.items.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-md transition-all group relative text-sm ${
                    isActive
                      ? 'bg-purple-600/10 text-purple-400 font-medium'
                      : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800/50'
                  }`
                }
              >
                <Icon size={16} className="flex-shrink-0" />
                <span className="truncate">{label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </div>

      <div className="mt-4">
        <SessionSwitcher />
      </div>
    </aside>
  )
}

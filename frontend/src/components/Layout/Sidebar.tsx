import { useState, useEffect } from 'react'
import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Shield, Repeat, Search, Zap, Replace, PauseCircle, GitCompare, FileSearch, Key, Globe, Users, FolderOpen, Play, Activity, Compass, Radio, BookOpen, Search as SearchIcon, Monitor, Wifi, ChevronDown, Bug, Puzzle, Settings2, AlertTriangle, FileText, Webhook, Lightbulb } from 'lucide-react'
import { apiClient } from '../../api/client'
import { SessionSwitcher } from './SessionSwitcher'

const navGroups = [
  {
    name: 'GENERAL',
    items: [
      { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, badgeKey: null },
      { to: '/recommendations', label: 'Recommendations', icon: Lightbulb, badgeKey: 'recommendations' },
      { to: '/projects', label: 'Projects', icon: FolderOpen, badgeKey: null },
      { to: '/organizer', label: 'Organizer', icon: BookOpen, badgeKey: null },
    ]
  },
  {
    name: 'TRAFFIC',
    items: [
      { to: '/proxy', label: 'Proxy', icon: Shield, badgeKey: null },
      { to: '/mitm', label: 'MITM', icon: Wifi, badgeKey: null },
      { to: '/interceptor', label: 'Interceptor', icon: PauseCircle, badgeKey: null },
      { to: '/repeater', label: 'Repeater', icon: Repeat, badgeKey: null },
      { to: '/match-replace', label: 'M&R Rules', icon: Replace, badgeKey: null },
      { to: '/websocket', label: 'WebSockets', icon: Globe, badgeKey: null },
    ]
  },
  {
    name: 'SCANNING & AUTOMATION',
    items: [
      { to: '/scanner', label: 'Scanner', icon: Search, badgeKey: null },
      { to: '/fuzzer', label: 'Fuzzer', icon: Zap, badgeKey: null },
      { to: '/content-discovery', label: 'Discovery', icon: Compass, badgeKey: null },
      { to: '/automation', label: 'AutoScan & Alerts', icon: Activity, badgeKey: null },
      { to: '/live-audit', label: 'Live Audit', icon: Radio, badgeKey: null },
    ]
  },
  {
    name: 'ADVANCED TOOLS',
    items: [
      { to: '/comparer', label: 'Comparer', icon: GitCompare, badgeKey: null },
      { to: '/auto-exploit', label: 'Auto Exploit', icon: Bug, badgeKey: null },
      { to: '/ws-messages', label: 'WebSocket MSG', icon: Globe, badgeKey: null },
      { to: '/triage', label: 'Smart Triage', icon: AlertTriangle, badgeKey: null },
      { to: '/auth-scan', label: 'Auth Scan', icon: Shield, badgeKey: null },
      { to: '/scan-policies', label: 'Scan Policies', icon: FileText, badgeKey: null },
      { to: '/automations', label: 'Automations', icon: Webhook, badgeKey: null },
      { to: '/plugins', label: 'Plugins', icon: Puzzle, badgeKey: null },
      { to: '/inspector', label: 'Inspector', icon: SearchIcon, badgeKey: null },
      { to: '/search', label: 'Search', icon: FileSearch, badgeKey: null },
    ]
  },
  {
    name: 'SETTINGS',
    items: [
      { to: '/proxy-config', label: 'Upstream Proxy', icon: Monitor, badgeKey: null },
      { to: '/settings', label: 'Settings', icon: Settings2, badgeKey: null },
      { to: '/auth', label: 'Authentication', icon: Key, badgeKey: null },
      { to: '/session', label: 'Session Handling', icon: Users, badgeKey: null },
      { to: '/scan-jobs', label: 'Scan Jobs', icon: Play, badgeKey: null },
      { to: '/compliance', label: 'Compliance', icon: FileText, badgeKey: null },
      { to: '/metrics', label: 'Metrics', icon: Activity, badgeKey: null },
    ]
  }
]

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false)
  const [expandedGroups, setExpandedGroups] = useState<string[]>(navGroups.map(g => g.name))
  const [badges, setBadges] = useState<Record<string, number>>({})

  useEffect(() => {
    const fetchBadges = async () => {
      try {
        const r = await apiClient.get('/api/recommendations/stats')
        const total = r.data.total || 0
        setBadges({ recommendations: total })
      } catch {}
    }
    fetchBadges()
    const interval = setInterval(fetchBadges, 10000)
    return () => clearInterval(interval)
  }, [])

  const toggleGroup = (name: string) => {
    setExpandedGroups(prev =>
      prev.includes(name) ? prev.filter(g => g !== name) : [...prev, name]
    )
  }

  return (
    <aside
      role="navigation"
      aria-label="Main navigation"
      className={`bg-gray-950 border-r border-gray-800 flex flex-col transition-all duration-200 ${collapsed ? 'w-14' : 'w-56'} shrink-0 overflow-hidden`}>
      <div className="p-3 border-b border-gray-800 flex items-center justify-between">
        {!collapsed && (
          <span className="text-sm font-bold text-purple-400 tracking-wider">NYX</span>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!collapsed}
          className="p-1 rounded hover:bg-gray-800 text-gray-500 hover:text-gray-300 transition-colors">
          <ChevronDown size={14} className={`transition-transform ${collapsed ? '-rotate-90' : ''}`} aria-hidden="true" />
        </button>
      </div>

      {!collapsed && (
        <div className="p-3 border-b border-gray-800">
          <SessionSwitcher />
        </div>
      )}

      <nav className="flex-1 overflow-y-auto p-2 space-y-1">
        {navGroups.map(group => {
          const isExpanded = expandedGroups.includes(group.name)
          return (
            <div key={group.name}>
              {!collapsed && (
                <button
                  onClick={() => toggleGroup(group.name)}
                  aria-expanded={isExpanded}
                  className="flex items-center gap-1 px-2 py-1.5 text-[10px] text-gray-600 hover:text-gray-400 w-full transition-colors">
                  <ChevronDown size={10} className={`transition-transform ${isExpanded ? '' : '-rotate-90'}`} aria-hidden="true" />
                  {group.name}
                </button>
              )}
              {isExpanded && group.items.map(item => (
                <NavLink key={item.to} to={item.to}
                  className={({ isActive }) =>
                    `flex items-center gap-2 px-2 py-1.5 rounded text-xs transition-colors ${
                      collapsed ? 'justify-center px-1' : ''
                    } ${
                      isActive
                        ? 'bg-purple-600/20 text-purple-300 border border-purple-700/30'
                        : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50 border border-transparent'
                    }`
                  }
                  title={collapsed ? item.label : undefined}
                >
                  <item.icon size={14} className="shrink-0" aria-hidden="true" />
                  {!collapsed && (
                    <span className="truncate flex-1">{item.label}</span>
                  )}
                  {!collapsed && item.badgeKey && badges[item.badgeKey] > 0 && (
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-amber-600/20 text-amber-400 border border-amber-700/30">
                      {badges[item.badgeKey]}
                    </span>
                  )}
                </NavLink>
              ))}
            </div>
          )
        })}
      </nav>
    </aside>
  )
}

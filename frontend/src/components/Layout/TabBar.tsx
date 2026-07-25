import { NavLink } from 'react-router-dom'
import { useRef, useEffect } from 'react'

const tabs = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/proxy', label: 'Proxy' },
  { to: '/mitm', label: 'MITM' },
  { to: '/repeater', label: 'Repeater' },
  { to: '/scanner', label: 'Scanner' },
  { to: '/scanner/active', label: 'Active Scan' },
  { to: '/scanner/custom', label: 'Custom' },
  { to: '/fuzzer', label: 'Fuzzer' },
  { to: '/crawler', label: 'Crawler' },
  { to: '/decoder', label: 'Decoder' },
  { to: '/match-replace', label: 'M&R' },
  { to: '/api-inspector', label: 'API' },
  { to: '/sequencer', label: 'Sequencer' },
  { to: '/reporter', label: 'Reporter' },
  { to: '/interceptor', label: 'Interceptor' },
  { to: '/comparer', label: 'Comparer' },
  { to: '/search', label: 'Search' },
  { to: '/auth', label: 'Auth' },
  { to: '/websocket', label: 'WebSocket' },
  { to: '/session', label: 'Session' },
  { to: '/projects', label: 'Projects' },
  { to: '/scan-jobs', label: 'Scan Jobs' },
  { to: '/automation', label: 'AutoScan' },
  { to: '/live-audit', label: 'Live Audit' },
  { to: '/content-discovery', label: 'Discovery' },
  { to: '/clickbandit', label: 'Clickbandit' },
  { to: '/scope', label: 'Scope' },
  { to: '/organizer', label: 'Organizer' },
  { to: '/inspector', label: 'Inspector' },
  { to: '/proxy-config', label: 'Proxy Config' },
]

export function TabBar() {
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      el.scrollLeft += e.deltaY
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [])

  return (
    <nav
      ref={scrollRef}
      className="flex items-center h-9 bg-gray-900 border-b border-gray-800 px-2 gap-0 overflow-x-auto overflow-y-hidden scrollbar-hide"
      style={{ scrollbarWidth: 'none', msOverflowStyle: 'none' }}
    >
      {tabs.map(({ to, label }) => (
        <NavLink
          key={to}
          to={to}
          end={to === '/scanner'}
          className={({ isActive }) =>
            `px-3 py-1.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap shrink-0 ${
              isActive
                ? 'border-purple-500 text-purple-400'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`
          }
        >
          {label}
        </NavLink>
      ))}
    </nav>
  )
}

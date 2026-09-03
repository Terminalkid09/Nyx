import { lazy, Suspense } from 'react'
import { Routes, Route } from 'react-router-dom'
import { Sidebar } from './components/Layout/Sidebar'
import { TabBar } from './components/Layout/TabBar'
import { ToastProvider } from './components/Toast'
import { ErrorBoundary } from './components/ErrorBoundary'
import { useWebSocket } from './hooks/useWebSocket'
import { WifiOff, RefreshCw, AlertTriangle, Loader2 } from 'lucide-react'

// Route-level code splitting: every page loads on demand so the initial
// bundle stays small (the app has 41 routes).
function lazyNamed<T extends Record<string, unknown>>(
  loader: () => Promise<T>,
  name: keyof T,
) {
  return lazy(() =>
    loader().then((m) => ({ default: m[name] as React.ComponentType })),
  )
}

const Dashboard = lazyNamed(() => import('./components/Dashboard'), 'Dashboard')
const PipelineConfig = lazyNamed(() => import('./components/PipelineConfig'), 'PipelineConfig')
const ProxyLog = lazyNamed(() => import('./components/ProxyLog/ProxyLog'), 'ProxyLog')
const Repeater = lazyNamed(() => import('./components/Repeater/Repeater'), 'Repeater')
const PassiveFindings = lazyNamed(() => import('./components/Scanner/PassiveFindings'), 'PassiveFindings')
const ActiveScanner = lazyNamed(() => import('./components/Scanner/ActiveScanner'), 'ActiveScanner')
const Fuzzer = lazyNamed(() => import('./components/Fuzzer/Fuzzer'), 'Fuzzer')
const Decoder = lazyNamed(() => import('./components/Decoder/Decoder'), 'Decoder')
const RuleManager = lazyNamed(() => import('./components/MatchReplace/RuleManager'), 'RuleManager')
const ApiInspector = lazyNamed(() => import('./components/ApiInspector/ApiInspector'), 'ApiInspector')
const Sequencer = lazyNamed(() => import('./components/Sequencer/Sequencer'), 'Sequencer')
const Reporter = lazyNamed(() => import('./components/Reporter/Reporter'), 'Reporter')
const Crawler = lazyNamed(() => import('./components/Crawler/Crawler'), 'Crawler')
const Interceptor = lazyNamed(() => import('./components/Interceptor/Interceptor'), 'Interceptor')
const Comparer = lazyNamed(() => import('./components/Comparer/Comparer'), 'Comparer')
const GlobalSearch = lazyNamed(() => import('./components/GlobalSearch/GlobalSearch'), 'GlobalSearch')
const AuthTester = lazyNamed(() => import('./components/AuthTester/AuthTester'), 'AuthTester')
const WebSocketViewer = lazyNamed(() => import('./components/WebSocketViewer/WebSocketViewer'), 'WebSocketViewer')
const SessionHandling = lazyNamed(() => import('./components/SessionHandling/SessionHandling'), 'SessionHandling')
const ProjectManager = lazyNamed(() => import('./components/ProjectManager/ProjectManager'), 'ProjectManager')
const ScanJobs = lazyNamed(() => import('./components/ScanJobs/ScanJobs'), 'ScanJobs')
const AutoScan = lazyNamed(() => import('./components/AutoScan/AutoScan'), 'AutoScan')
const ContentDiscovery = lazyNamed(() => import('./components/ContentDiscovery'), 'ContentDiscovery')
const Organizer = lazyNamed(() => import('./components/Organizer'), 'Organizer')
const Inspector = lazyNamed(() => import('./components/Inspector'), 'Inspector')
const Clickbandit = lazyNamed(() => import('./components/Clickbandit'), 'Clickbandit')
const TargetScope = lazyNamed(() => import('./components/TargetScope'), 'TargetScope')
const ProxyConfigPage = lazyNamed(() => import('./components/ProxyConfig'), 'ProxyConfigPage')
const MitmPage = lazyNamed(() => import('./components/Mitm/Mitm'), 'MitmPage')
const OnboardingWizard = lazy(() => import('./components/OnboardingWizard'))
const LiveAudit = lazyNamed(() => import('./components/LiveAudit'), 'LiveAudit')
const AutoExploit = lazyNamed(() => import('./components/AutoExploit/AutoExploit'), 'AutoExploit')
const Recommendations = lazyNamed(() => import('./components/Recommendations/Recommendations'), 'Recommendations')
const Plugins = lazyNamed(() => import('./components/Plugins/Plugins'), 'Plugins')
const Settings = lazyNamed(() => import('./components/Settings/Settings'), 'Settings')
const Triage = lazyNamed(() => import('./components/Triage/Triage'), 'Triage')
const ScanPolicies = lazyNamed(() => import('./components/ScanPolicies/ScanPolicies'), 'ScanPolicies')
const WebSocketMessages = lazyNamed(() => import('./components/WebSocketMessages/WebSocketMessages'), 'WebSocketMessages')
const Automations = lazyNamed(() => import('./components/Automations/Automations'), 'Automations')
const AuthScan = lazyNamed(() => import('./components/AuthScan/AuthScan'), 'AuthScan')
const CustomChecks = lazyNamed(() => import('./components/Scanner/CustomChecks'), 'CustomChecks')
const Compliance = lazyNamed(() => import('./components/Compliance/Compliance'), 'Compliance')
const Metrics = lazyNamed(() => import('./components/Metrics/Metrics'), 'Metrics')
const Network = lazyNamed(() => import('./components/Network/Network'), 'Network')

function RouteFallback() {
  return (
    <div className="flex items-center justify-center h-full text-gray-500" role="status" aria-live="polite">
      <Loader2 size={20} className="animate-spin mr-2" aria-hidden="true" />
      Loading…
    </div>
  )
}

// ── WS Status Banner ─────────────────────────────────────────────────────────
function WsBanner({ state }: { state: 'connected' | 'disconnected' | 'error' }) {
  if (state === 'connected') return null

  const isError = state === 'error'

  return (
    <div
      className={`flex items-center justify-between px-4 py-1.5 text-xs font-medium ${
        isError
          ? 'bg-red-900/40 border-b border-red-700/40 text-red-300'
          : 'bg-yellow-900/30 border-b border-yellow-700/30 text-yellow-300'
      }`}
    >
      <div className="flex items-center gap-2">
        {isError ? (
          <AlertTriangle size={12} className="shrink-0" />
        ) : (
          <WifiOff size={12} className="shrink-0 animate-pulse" />
        )}
        {isError
          ? 'WebSocket connection lost permanently. Refresh the page or restart Nyx.'
          : 'Connecting to Nyx backend… live traffic updates paused.'}
      </div>
      {isError && (
        <button
          onClick={() => window.location.reload()}
          className="flex items-center gap-1 px-2 py-0.5 rounded bg-red-700/40 hover:bg-red-700/60 transition-colors"
        >
          <RefreshCw size={11} />
          Refresh
        </button>
      )}
    </div>
  )
}

// ── Per-route ErrorBoundary wrapper ──────────────────────────────────────────
function RouteErrorBoundary({ children }: { children: React.ReactNode }) {
  return <ErrorBoundary>{children}</ErrorBoundary>
}

export default function App() {
  const { wsState } = useWebSocket()

  return (
    <ErrorBoundary>
      <ToastProvider>
        <OnboardingWizard />
        <div className="flex h-screen bg-gray-950 text-gray-200 overflow-hidden">
          <Sidebar />
          <div className="flex flex-col flex-1 min-w-0">
            <TabBar />
            {/* WS connectivity banner — only visible when disconnected */}
            <WsBanner state={wsState} />
            <main className="main-content">
              <Suspense fallback={<RouteFallback />}>
                <Routes>
                <Route path="/" element={<RouteErrorBoundary><Dashboard /></RouteErrorBoundary>} />
                <Route path="/dashboard" element={<RouteErrorBoundary><Dashboard /></RouteErrorBoundary>} />
                <Route path="/scan/new" element={<RouteErrorBoundary><PipelineConfig /></RouteErrorBoundary>} />
                <Route path="/proxy" element={<RouteErrorBoundary><ProxyLog /></RouteErrorBoundary>} />
                <Route path="/repeater" element={<RouteErrorBoundary><Repeater /></RouteErrorBoundary>} />
                <Route path="/scanner" element={<RouteErrorBoundary><PassiveFindings /></RouteErrorBoundary>} />
                <Route path="/scanner/active" element={<RouteErrorBoundary><ActiveScanner /></RouteErrorBoundary>} />
                <Route path="/scanner/custom" element={<RouteErrorBoundary><CustomChecks /></RouteErrorBoundary>} />
                <Route path="/fuzzer" element={<RouteErrorBoundary><Fuzzer /></RouteErrorBoundary>} />
                <Route path="/decoder" element={<RouteErrorBoundary><Decoder /></RouteErrorBoundary>} />
                <Route path="/match-replace" element={<RouteErrorBoundary><RuleManager /></RouteErrorBoundary>} />
                <Route path="/api-inspector" element={<RouteErrorBoundary><ApiInspector /></RouteErrorBoundary>} />
                <Route path="/sequencer" element={<RouteErrorBoundary><Sequencer /></RouteErrorBoundary>} />
                <Route path="/reporter" element={<RouteErrorBoundary><Reporter /></RouteErrorBoundary>} />
                <Route path="/crawler" element={<RouteErrorBoundary><Crawler /></RouteErrorBoundary>} />
                <Route path="/interceptor" element={<RouteErrorBoundary><Interceptor /></RouteErrorBoundary>} />
                <Route path="/comparer" element={<RouteErrorBoundary><Comparer /></RouteErrorBoundary>} />
                <Route path="/search" element={<RouteErrorBoundary><GlobalSearch /></RouteErrorBoundary>} />
                <Route path="/auth" element={<RouteErrorBoundary><AuthTester /></RouteErrorBoundary>} />
                <Route path="/websocket" element={<RouteErrorBoundary><WebSocketViewer /></RouteErrorBoundary>} />
                <Route path="/session" element={<RouteErrorBoundary><SessionHandling /></RouteErrorBoundary>} />
                <Route path="/projects" element={<RouteErrorBoundary><ProjectManager /></RouteErrorBoundary>} />
                <Route path="/scan-jobs" element={<RouteErrorBoundary><ScanJobs /></RouteErrorBoundary>} />
                <Route path="/automation" element={<RouteErrorBoundary><AutoScan /></RouteErrorBoundary>} />
                <Route path="/content-discovery" element={<RouteErrorBoundary><ContentDiscovery /></RouteErrorBoundary>} />
                <Route path="/organizer" element={<RouteErrorBoundary><Organizer /></RouteErrorBoundary>} />
                <Route path="/recommendations" element={<RouteErrorBoundary><Recommendations /></RouteErrorBoundary>} />
                <Route path="/auto-exploit" element={<RouteErrorBoundary><AutoExploit /></RouteErrorBoundary>} />
                <Route path="/plugins" element={<RouteErrorBoundary><Plugins /></RouteErrorBoundary>} />
                <Route path="/settings" element={<RouteErrorBoundary><Settings /></RouteErrorBoundary>} />
                <Route path="/triage" element={<RouteErrorBoundary><Triage /></RouteErrorBoundary>} />
                <Route path="/scan-policies" element={<RouteErrorBoundary><ScanPolicies /></RouteErrorBoundary>} />
                <Route path="/ws-messages" element={<RouteErrorBoundary><WebSocketMessages /></RouteErrorBoundary>} />
                <Route path="/automations" element={<RouteErrorBoundary><Automations /></RouteErrorBoundary>} />
                <Route path="/auth-scan" element={<RouteErrorBoundary><AuthScan /></RouteErrorBoundary>} />
                <Route path="/inspector" element={<RouteErrorBoundary><Inspector /></RouteErrorBoundary>} />
                <Route path="/clickbandit" element={<RouteErrorBoundary><Clickbandit /></RouteErrorBoundary>} />
                <Route path="/scope" element={<RouteErrorBoundary><TargetScope /></RouteErrorBoundary>} />
                <Route path="/proxy-config" element={<RouteErrorBoundary><ProxyConfigPage /></RouteErrorBoundary>} />
                <Route path="/live-audit" element={<RouteErrorBoundary><LiveAudit /></RouteErrorBoundary>} />
                <Route path="/mitm" element={<RouteErrorBoundary><MitmPage /></RouteErrorBoundary>} />
                <Route path="/compliance" element={<RouteErrorBoundary><Compliance /></RouteErrorBoundary>} />
                <Route path="/metrics" element={<RouteErrorBoundary><Metrics /></RouteErrorBoundary>} />
                <Route path="/network" element={<RouteErrorBoundary><Network /></RouteErrorBoundary>} />
                </Routes>
              </Suspense>
            </main>
          </div>
        </div>
      </ToastProvider>
    </ErrorBoundary>
  )
}

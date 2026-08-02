import { Routes, Route } from 'react-router-dom'
import { Sidebar } from './components/Layout/Sidebar'
import { TabBar } from './components/Layout/TabBar'
import { ToastProvider } from './components/Toast'
import { ErrorBoundary } from './components/ErrorBoundary'
import { useWebSocket } from './hooks/useWebSocket'
import { Dashboard } from './components/Dashboard'
import { PipelineConfig } from './components/PipelineConfig'
import { ProxyLog } from './components/ProxyLog/ProxyLog'
import { Repeater } from './components/Repeater/Repeater'
import { PassiveFindings } from './components/Scanner/PassiveFindings'
import { ActiveScanner } from './components/Scanner/ActiveScanner'
import { Fuzzer } from './components/Fuzzer/Fuzzer'
import { Decoder } from './components/Decoder/Decoder'
import { RuleManager } from './components/MatchReplace/RuleManager'
import { ApiInspector } from './components/ApiInspector/ApiInspector'
import { Sequencer } from './components/Sequencer/Sequencer'
import { Reporter } from './components/Reporter/Reporter'
import { Crawler } from './components/Crawler/Crawler'
import { Interceptor } from './components/Interceptor/Interceptor'
import { Comparer } from './components/Comparer/Comparer'
import { GlobalSearch } from './components/GlobalSearch/GlobalSearch'
import { AuthTester } from './components/AuthTester/AuthTester'
import { WebSocketViewer } from './components/WebSocketViewer/WebSocketViewer'
import { SessionHandling } from './components/SessionHandling/SessionHandling'
import { ProjectManager } from './components/ProjectManager/ProjectManager'
import { ScanJobs } from './components/ScanJobs/ScanJobs'
import { AutoScan } from './components/AutoScan/AutoScan'
import { ContentDiscovery } from './components/ContentDiscovery'
import { Organizer } from './components/Organizer'
import { Inspector } from './components/Inspector'
import { Clickbandit } from './components/Clickbandit'
import { TargetScope } from './components/TargetScope'
import { ProxyConfigPage } from './components/ProxyConfig'
import { MitmPage } from './components/Mitm/Mitm'
import OnboardingWizard from './components/OnboardingWizard'
import { LiveAudit } from './components/LiveAudit'
import { AutoExploit } from './components/AutoExploit/AutoExploit'
import { Recommendations } from './components/Recommendations/Recommendations'
import { Plugins } from './components/Plugins/Plugins'
import { Settings } from './components/Settings/Settings'
import { Triage } from './components/Triage/Triage'
import { ScanPolicies } from './components/ScanPolicies/ScanPolicies'
import { WebSocketMessages } from './components/WebSocketMessages/WebSocketMessages'
import { Automations } from './components/Automations/Automations'
import { AuthScan } from './components/AuthScan/AuthScan'
import { CustomChecks } from './components/Scanner/CustomChecks'
import { WifiOff, RefreshCw, AlertTriangle } from 'lucide-react'

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
              </Routes>
            </main>
          </div>
        </div>
      </ToastProvider>
    </ErrorBoundary>
  )
}

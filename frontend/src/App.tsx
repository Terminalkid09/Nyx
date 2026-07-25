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
import { CustomChecks } from './components/Scanner/CustomChecks'

export default function App() {
  useWebSocket()

  return (
    <ErrorBoundary>
    <ToastProvider>
      <OnboardingWizard />
      <div className="flex h-screen bg-gray-950 text-gray-200 overflow-hidden">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0">
        <TabBar />
        <main className="flex-1 overflow-hidden">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/scan/new" element={<PipelineConfig />} />
            <Route path="/proxy" element={<ProxyLog />} />
            <Route path="/repeater" element={<Repeater />} />
            <Route path="/scanner" element={<PassiveFindings />} />
            <Route path="/scanner/active" element={<ActiveScanner />} />
            <Route path="/scanner/custom" element={<CustomChecks />} />
            <Route path="/fuzzer" element={<Fuzzer />} />
            <Route path="/decoder" element={<Decoder />} />
            <Route path="/match-replace" element={<RuleManager />} />
            <Route path="/api-inspector" element={<ApiInspector />} />
            <Route path="/sequencer" element={<Sequencer />} />
            <Route path="/reporter" element={<Reporter />} />
            <Route path="/crawler" element={<Crawler />} />
            <Route path="/interceptor" element={<Interceptor />} />
            <Route path="/comparer" element={<Comparer />} />
            <Route path="/search" element={<GlobalSearch />} />
            <Route path="/auth" element={<AuthTester />} />
            <Route path="/websocket" element={<WebSocketViewer />} />
            <Route path="/session" element={<SessionHandling />} />
            <Route path="/projects" element={<ProjectManager />} />
            <Route path="/scan-jobs" element={<ScanJobs />} />
            <Route path="/automation" element={<AutoScan />} />
            <Route path="/content-discovery" element={<ContentDiscovery />} />
            <Route path="/organizer" element={<Organizer />} />
            <Route path="/inspector" element={<Inspector />} />
            <Route path="/clickbandit" element={<Clickbandit />} />
            <Route path="/scope" element={<TargetScope />} />
            <Route path="/proxy-config" element={<ProxyConfigPage />} />
            <Route path="/live-audit" element={<LiveAudit />} />
            <Route path="/mitm" element={<MitmPage />} />
          </Routes>
        </main>
      </div>
      </div>
    </ToastProvider>
    </ErrorBoundary>
  )
}

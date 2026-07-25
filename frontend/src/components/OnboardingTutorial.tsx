import { useState } from 'react'
import { X, Shield, Radio, Activity, Repeat, Bug, ChevronRight } from 'lucide-react'

export function OnboardingTutorial({ onClose }: { onClose?: () => void }) {
  const [step, setStep] = useState(0)

  const steps = [
    {
      title: "Step 1: Configure your Proxy",
      description: "Point your browser or FoxyProxy to 127.0.0.1:8080 to start routing traffic through Nyx.",
      visual: (
        <div className="flex items-center justify-center gap-4 py-8">
          <div className="flex flex-col items-center gap-2">
            <div className="w-16 h-16 rounded-xl bg-gray-800 flex items-center justify-center border border-gray-700">
              <GlobeIcon />
            </div>
            <span className="text-xs text-gray-400 font-mono">Browser</span>
          </div>
          
          <div className="flex flex-col items-center">
            <div className="h-0.5 w-16 bg-gradient-to-r from-gray-700 to-purple-500 relative">
              <div className="absolute right-0 -top-1.5 w-3 h-3 border-t-2 border-r-2 border-purple-500 transform rotate-45"></div>
            </div>
            <span className="text-[10px] text-gray-500 mt-2 font-mono">:8080</span>
          </div>

          <div className="flex flex-col items-center gap-2">
            <div className="w-20 h-20 rounded-xl bg-purple-900/30 flex items-center justify-center border border-purple-500 shadow-[0_0_20px_rgba(168,85,247,0.2)]">
              <Shield size={32} className="text-purple-400" />
            </div>
            <span className="text-xs text-purple-400 font-bold tracking-widest">NYX</span>
          </div>
        </div>
      )
    },
    {
      title: "Step 2: Intercept & Replay",
      description: "Once traffic flows, view it in the Proxy tab. Send interesting requests to the Repeater to modify and replay them.",
      visual: (
        <div className="flex items-center justify-center gap-4 py-8">
          <div className="flex flex-col items-center gap-2">
            <div className="w-16 h-16 rounded-xl bg-blue-900/20 flex items-center justify-center border border-blue-800">
              <Radio size={24} className="text-blue-400" />
            </div>
            <span className="text-xs text-gray-400 font-mono">Proxy Log</span>
          </div>
          
          <div className="flex items-center justify-center relative w-16">
            <div className="absolute w-full h-0.5 bg-gray-700"></div>
            <div className="z-10 bg-gray-800 border border-gray-600 px-2 py-1 rounded text-[10px] text-gray-300 shadow-lg cursor-pointer hover:bg-gray-700 transition-colors">
              Send to Repeater
            </div>
          </div>

          <div className="flex flex-col items-center gap-2">
            <div className="w-16 h-16 rounded-xl bg-green-900/20 flex items-center justify-center border border-green-800">
              <Repeat size={24} className="text-green-400" />
            </div>
            <span className="text-xs text-gray-400 font-mono">Repeater</span>
          </div>
        </div>
      )
    },
    {
      title: "Step 3: Organize with Projects",
      description: "Use Projects to isolate data (e.g. 'Client A' vs 'Bug Bounty Target B'). Everything you capture and find will be safely scoped to your active project.",
      visual: (
        <div className="flex items-center justify-center gap-4 py-8">
          <div className="flex flex-col items-center gap-2">
            <div className="w-16 h-16 rounded-xl bg-orange-900/20 flex items-center justify-center border border-orange-800">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-orange-400"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"></path></svg>
            </div>
            <span className="text-xs text-gray-400 font-mono">Project A</span>
          </div>
          <div className="flex flex-col items-center justify-center gap-2">
            <div className="w-8 h-8 rounded-full bg-gray-800 flex items-center justify-center">
              <span className="text-xs text-gray-500">vs</span>
            </div>
          </div>
          <div className="flex flex-col items-center gap-2">
            <div className="w-16 h-16 rounded-xl bg-indigo-900/20 flex items-center justify-center border border-indigo-800">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-indigo-400"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"></path></svg>
            </div>
            <span className="text-xs text-gray-400 font-mono">Project B</span>
          </div>
        </div>
      )
    },
    {
      title: "Step 4: Handling Authentication",
      description: "The Auth module helps you manage JWTs and OAuth tokens. You can analyze tokens, track their expiration, or test for common auth bypass vulnerabilities.",
      visual: (
        <div className="flex items-center justify-center gap-4 py-8">
          <div className="flex flex-col items-center gap-2">
            <div className="w-20 h-12 rounded bg-gray-800 border border-gray-700 flex items-center justify-center">
              <span className="text-[10px] text-pink-500 font-mono">eyJhbG...</span>
            </div>
            <span className="text-[10px] text-gray-500">JWT Header</span>
          </div>
          <div className="h-0.5 w-8 bg-gray-700"></div>
          <div className="flex flex-col items-center gap-2">
            <div className="w-24 h-12 rounded bg-gray-800 border border-gray-700 flex items-center justify-center">
              <span className="text-[10px] text-purple-400 font-mono">eyJzdWI...</span>
            </div>
            <span className="text-[10px] text-gray-500">Payload (User ID)</span>
          </div>
          <div className="h-0.5 w-8 bg-gray-700"></div>
          <div className="flex flex-col items-center gap-2">
            <div className="w-20 h-12 rounded bg-gray-800 border border-gray-700 flex items-center justify-center">
              <span className="text-[10px] text-blue-400 font-mono">SflKxw...</span>
            </div>
            <span className="text-[10px] text-gray-500">Signature</span>
          </div>
        </div>
      )
    },
    {
      title: "Step 5: Automate your Workflow",
      description: "All modules in Nyx communicate in real-time. Enable AutoScan to passively analyze proxy traffic, and configure Webhooks for instant Slack/Discord alerts.",
      visual: (
        <div className="flex items-center justify-center gap-4 py-8">
          <div className="flex flex-col items-center gap-2">
            <div className="w-16 h-16 rounded-xl bg-yellow-900/20 flex items-center justify-center border border-yellow-800">
              <Activity size={24} className="text-yellow-400" />
            </div>
            <span className="text-xs text-gray-400 font-mono">AutoScan</span>
          </div>
          
          <div className="flex flex-col items-center">
             <div className="h-0.5 w-12 bg-gradient-to-r from-yellow-700 to-red-500 relative">
              <div className="absolute right-0 -top-1.5 w-3 h-3 border-t-2 border-r-2 border-red-500 transform rotate-45"></div>
            </div>
            <Bug size={12} className="text-red-400 mt-2 absolute" />
          </div>

          <div className="flex flex-col items-center gap-2">
            <div className="w-16 h-16 rounded-xl bg-red-900/20 flex items-center justify-center border border-red-800">
              <AlertIcon />
            </div>
            <span className="text-xs text-gray-400 font-mono">Webhook Alert</span>
          </div>
        </div>
      )
    }
  ]

  return (
    <div className="relative overflow-hidden rounded-xl bg-gradient-to-br from-gray-900 to-gray-800 border border-purple-500/30 mb-6 shadow-lg shadow-purple-900/20">
      <div className="absolute top-0 left-0 w-1 h-full bg-purple-500"></div>
      
      <button onClick={onClose} className="absolute top-3 right-3 text-gray-500 hover:text-gray-300 transition-colors">
        <X size={18} />
      </button>

      <div className="p-6">
        <div className="flex items-center gap-2 mb-2">
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-400 uppercase tracking-wider">
            Quick Start
          </span>
          <h2 className="text-lg font-bold text-gray-100">Welcome to Nyx Security Suite</h2>
        </div>
        <p className="text-sm text-gray-400 mb-6 max-w-2xl">
          Nyx is an enterprise-grade automated proxy. Let's walk through the basic workflow to get you started on your first security audit.
        </p>

        <div className="bg-gray-950/50 rounded-lg border border-gray-800 p-1 flex flex-col md:flex-row min-h-[220px]">
          
          {/* Sidebar controls */}
          <div className="w-full md:w-1/3 flex flex-row md:flex-col gap-1 p-2 border-b md:border-b-0 md:border-r border-gray-800">
            {steps.map((s, i) => (
              <button
                key={i}
                onClick={() => setStep(i)}
                className={`text-left px-3 py-2 rounded text-xs font-medium transition-all flex items-center justify-between group ${
                  step === i 
                    ? 'bg-purple-600 text-white shadow-md' 
                    : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                }`}
              >
                <span>{s.title}</span>
                <ChevronRight size={14} className={`transition-transform ${step === i ? 'translate-x-1' : 'opacity-0 group-hover:opacity-100 group-hover:translate-x-1'}`} />
              </button>
            ))}
          </div>

          {/* Visual Content */}
          <div className="flex-1 p-4 flex flex-col justify-between">
            <div className="animate-in fade-in slide-in-from-right-4 duration-500">
              {steps[step].visual}
            </div>
            <div className="text-center mt-auto animate-in fade-in duration-700">
              <p className="text-sm text-gray-300">{steps[step].description}</p>
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}

function GlobeIcon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-gray-400">
      <circle cx="12" cy="12" r="10"></circle>
      <line x1="2" y1="12" x2="22" y2="12"></line>
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
    </svg>
  )
}

function AlertIcon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-red-400">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
      <line x1="12" y1="9" x2="12" y2="13"></line>
      <line x1="12" y1="17" x2="12.01" y2="17"></line>
    </svg>
  )
}

import { Component, ReactNode } from 'react'

interface Props { children: ReactNode }
interface State { hasError: boolean; error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  handleReset = () => this.setState({ hasError: false, error: null })

  render() {
    if (this.state.hasError) {
      return (
        <div
          role="alert"
          aria-live="assertive"
          className="flex flex-col items-center justify-center h-screen bg-gray-950 text-gray-200 p-8">
          <div className="bg-red-900/30 border border-red-800 rounded-lg p-6 max-w-lg w-full">
            <h2 className="text-lg font-bold text-red-400 mb-2">Something went wrong</h2>
            <pre className="text-xs text-red-300 bg-red-950/50 rounded p-3 overflow-auto max-h-40 mb-4 font-mono" aria-label="Error details">
              {this.state.error?.message || 'Unknown error'}
            </pre>
            <button
              onClick={this.handleReset}
              aria-label="Reload user interface"
              className="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-purple-500"
            >
              Reload UI
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

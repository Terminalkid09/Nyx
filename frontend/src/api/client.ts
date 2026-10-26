import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || ''

export const apiClient = axios.create({
  baseURL: API_URL,
  timeout: 30000,
})

const desktop = typeof window !== 'undefined' ? (window as any).nyxDesktop : undefined

// In the Electron app, pick up the backend's persisted API key and send it on
// every request. Localhost calls are accepted without a key today; this keeps
// the shell working unchanged if the API is ever bound beyond loopback.
if (desktop?.getApiKey) {
  desktop
    .getApiKey()
    .then((key: string | null) => {
      if (key) {
        apiClient.defaults.headers.common['X-API-Key'] = key
      }
    })
    .catch(() => {})
}

// SEC-03b: in a packaged build the backend also rejects loopback calls that do
// not carry the token it generated at boot (any local process can reach
// 127.0.0.1:8000). Keep it cached per page load; the shell re-reads the file on
// every request, so clearing the cache is enough to follow a backend restart.
let sessionToken: string | null = null
let sessionTokenRequest: Promise<string | null> | null = null

async function getSessionToken(): Promise<string | null> {
  if (sessionToken || !desktop?.getSessionToken) return sessionToken
  if (!sessionTokenRequest) {
    sessionTokenRequest = desktop
      .getSessionToken()
      .then((token: string | null) => (sessionToken = token ?? null))
      .catch(() => null)
      .finally(() => {
        sessionTokenRequest = null
      })
  }
  return sessionTokenRequest
}

apiClient.interceptors.request.use(async (config) => {
  const token = await getSessionToken()
  if (token) {
    config.headers.set('X-Nyx-Token', token)
  }
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const config = error.config
    const detail = String(error.response?.data?.detail ?? '')
    // The backend rotated its token (restart): drop the cache and retry once.
    if (
      error.response?.status === 403 &&
      detail.includes('X-Nyx-Token') &&
      config &&
      !(config as any).__nyxTokenRetry
    ) {
      ;(config as any).__nyxTokenRetry = true
      sessionToken = null
      const token = await getSessionToken()
      if (token) {
        config.headers.set('X-Nyx-Token', token)
        return apiClient.request(config)
      }
    }
    console.error('[Nyx API] Error:', error.response?.status, error.message)
    return Promise.reject(error)
  },
)

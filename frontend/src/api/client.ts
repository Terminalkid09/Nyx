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

/** Drop the cached token so the next call re-reads it from the shell. */
export function invalidateSessionToken() {
  sessionToken = null
}

export { getSessionToken }

apiClient.interceptors.request.use(async (config) => {
  const token = await getSessionToken()
  if (token) {
    config.headers.set('X-Nyx-Token', token)
  }
  return config
})

// 429 handling: at most two retries, and only for requests that are safe to
// repeat. A POST/PUT is left to the caller — replaying it could duplicate the
// work the user asked for.
const MAX_429_RETRIES = 2
const IDEMPOTENT_METHODS = new Set(['get', 'head', 'options'])

/** Convert a Retry-After header (seconds or HTTP date) to a bounded delay. */
function retryAfterMs(value: unknown): number | null {
  if (typeof value !== 'string' || !value.trim()) return null
  const seconds = Number(value)
  const ms = Number.isFinite(seconds)
    ? seconds * 1000
    : Date.parse(value) - Date.now()
  if (!Number.isFinite(ms)) return null
  return Math.min(Math.max(ms, 1000), 10_000)
}

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
    // A bulk sweep (or a burst of component mounts) can legitimately exceed
    // the API rate limiter. Retry the idempotent calls with backoff instead of
    // surfacing a 429 as a failure; the limiter's Retry-After wins when sent.
    if (error.response?.status === 429 && config) {
      const attempts = Number((config as any).__nyx429Retry ?? 0)
      const method = String(config.method ?? 'get').toLowerCase()
      if (attempts < MAX_429_RETRIES && IDEMPOTENT_METHODS.has(method)) {
        ;(config as any).__nyx429Retry = attempts + 1
        const wait = retryAfterMs(error.response.headers?.['retry-after'])
        await new Promise((resolve) =>
          setTimeout(resolve, wait ?? 300 * 2 ** attempts),
        )
        return apiClient.request(config)
      }
    }
    console.error('[Nyx API] Error:', error.response?.status, error.message)
    return Promise.reject(error)
  },
)

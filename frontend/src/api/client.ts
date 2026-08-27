import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || ''

export const apiClient = axios.create({
  baseURL: API_URL,
  timeout: 30000,
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('[Nyx API] Error:', error.response?.status, error.message)
    return Promise.reject(error)
  },
)

// In the Electron app, pick up the backend's persisted API key and send it on
// every request. Localhost calls are accepted without a key today; this keeps
// the shell working unchanged if the API is ever bound beyond loopback.
if (typeof window !== 'undefined' && (window as any).nyxDesktop?.getApiKey) {
  ;(window as any).nyxDesktop
    .getApiKey()
    .then((key: string | null) => {
      if (key) {
        apiClient.defaults.headers.common['X-API-Key'] = key
      }
    })
    .catch(() => {})
}

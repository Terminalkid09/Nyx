import { apiClient } from '../client'
import { AuthJwtResult } from '../../types'

export async function decodeJwt(token: string): Promise<AuthJwtResult> {
  const { data } = await apiClient.post('/api/auth/jwt/decode', { token })
  return data
}

export async function analyzeJwt(token: string): Promise<{ issues: { type: string; severity: string; description: string }[] }> {
  const { data } = await apiClient.post('/api/auth/jwt/analyze', { token })
  return data
}

export async function bruteJwt(token: string): Promise<{ found: boolean; secret?: string; attempts: number }> {
  const { data } = await apiClient.post('/api/auth/jwt/brute', { token })
  return data
}

export async function crackJwt(token: string, secret: string): Promise<{ valid: boolean }> {
  const { data } = await apiClient.post('/api/auth/jwt/crack', { token, secret })
  return data
}

export async function debugOAuth(params: Record<string, string>): Promise<{ issues: string[] }> {
  const { data } = await apiClient.post('/api/auth/oauth/debug', params)
  return data
}

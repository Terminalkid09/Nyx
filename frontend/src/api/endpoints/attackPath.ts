import { apiClient } from '../client'

export interface AttackPathNode {
  id: string
  title: string
  severity: string
  host: string
  cwe: string | null
  request_id: string | null
}

export interface AttackPathEdge {
  source: string
  target: string
  /** ``same_request`` or ``exposure_enables_finding``. */
  reason: string
}

export interface AttackPathGraph {
  nodes: AttackPathNode[]
  edges: AttackPathEdge[]
}

export async function getAttackPath(sessionId: string): Promise<AttackPathGraph> {
  const { data } = await apiClient.get<AttackPathGraph>(`/api/attack-path/${sessionId}`)
  return data
}

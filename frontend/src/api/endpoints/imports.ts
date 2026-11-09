import { apiClient } from '../client'

export interface OpenApiParameter {
  name: string
  in: string
  required: boolean
  type: string | null
}

export interface OpenApiEndpoint {
  method: string
  path: string
  url: string
  operation_id: string | null
  summary: string | null
  parameters: OpenApiParameter[]
  content_types: string[]
  security: string[]
  authenticated: boolean
  // Only present on Burp exports: the status Burp observed when it captured
  // the request.
  status?: number | null
}

export interface OpenApiWarning {
  severity: string
  code: string
  message: string
  method: string | null
  path: string | null
}

export interface OpenApiScopeResult {
  added: string[]
  skipped: string[]
}

export interface OpenApiInventory {
  spec: { version: string; title: string; api_version: string }
  servers: string[]
  endpoint_count: number
  method_counts: Record<string, number>
  endpoints: OpenApiEndpoint[]
  warnings: OpenApiWarning[]
  filename?: string
  // Only present on Burp exports: how many <item> entries the file held before
  // deduplication by (method, path).
  item_count?: number
  scope?: OpenApiScopeResult
}

export interface OpenApiImportRequest {
  document: string
  filename?: string
  session_id?: string
  apply_scope?: boolean
}

export async function importOpenApi(body: OpenApiImportRequest): Promise<OpenApiInventory> {
  const { data } = await apiClient.post<OpenApiInventory>('/api/import/openapi', body)
  return data
}

export async function importBurp(body: OpenApiImportRequest): Promise<OpenApiInventory> {
  const { data } = await apiClient.post<OpenApiInventory>('/api/import/burp', body, {
    // A large export is 64 MB of XML: parsing takes a moment server-side.
    timeout: 120000,
  })
  return data
}

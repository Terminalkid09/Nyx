import { apiClient } from '../client'

export interface OwaspCategory {
  id: string
  title: string
  finding_count: number
  finding_ids: string[]
  findings: Array<{
    id: string
    title: string
    severity: string
    cwe: string | null
    description: string
    host: string
    path: string
    cvss_score: number | null
  }>
  pass: boolean
}

export interface OwaspReport {
  report_id: string
  generated_at: string
  framework: string
  summary: {
    total_findings: number
    severity_breakdown: Record<string, number>
    categories_with_findings: number
    categories_clean: number
  }
  categories: OwaspCategory[]
}

export interface PciDssRequirement {
  requirement_id: string
  title: string
  status: 'PASS' | 'FAIL'
  violations: any[]
  violation_count: number
}

export interface PciDssReport {
  report_id: string
  generated_at: string
  framework: string
  summary: {
    total_requirements: number
    passed: number
    failed: number
    total_violations: number
  }
  requirements: PciDssRequirement[]
}

export interface GdprArticle {
  article: string
  title: string
  status: 'PASS' | 'FAIL'
  violations: any[]
  violation_count: number
}

export interface GdprReport {
  report_id: string
  generated_at: string
  framework: string
  summary: {
    total_articles: number
    passed: number
    failed: number
    total_violations: number
  }
  articles: GdprArticle[]
}

export interface ComplianceStatus {
  total_findings: number
  owasp_categories_with_findings: number
  owasp_categories_clean: number
  pci_requirements_passed: number
  pci_requirements_failed: number
  overall_risk: 'HIGH' | 'LOW'
}

export async function getOwaspReport(): Promise<OwaspReport> {
  const { data } = await apiClient.get('/api/compliance/owasp')
  return data
}

export async function getPciDssReport(): Promise<PciDssReport> {
  const { data } = await apiClient.get('/api/compliance/pci-dss')
  return data
}

export async function getGdprReport(): Promise<GdprReport> {
  const { data } = await apiClient.get('/api/compliance/gdpr')
  return data
}

export async function getComplianceStatus(): Promise<ComplianceStatus> {
  const { data } = await apiClient.get('/api/compliance/status')
  return data
}
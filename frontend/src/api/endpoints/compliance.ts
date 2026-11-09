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

export type MeasureStatus = 'PASS' | 'FAIL' | 'NOT_ASSESSED'

export interface Measure {
  title: string
  status: MeasureStatus
  violations: any[]
  violation_count: number
}

export interface Nis2Measure extends Measure {
  measure_id: string
}

export interface IsoControl extends Measure {
  control_id: string
}

interface MeasureReport<T> {
  report_id: string
  generated_at: string
  framework: string
  scope: { basis: string; caveat: string }
  summary: {
    total: number
    passed: number
    failed: number
    not_assessed: number
    total_violations: number
  }
  measures?: T[]
  controls?: T[]
}

export type Nis2Report = MeasureReport<Nis2Measure> & { measures: Nis2Measure[] }
export type Iso27001Report = MeasureReport<IsoControl> & { controls: IsoControl[] }

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

export async function getNis2Report(): Promise<Nis2Report> {
  const { data } = await apiClient.get('/api/compliance/nis2')
  return data
}

export async function getIso27001Report(): Promise<Iso27001Report> {
  const { data } = await apiClient.get('/api/compliance/iso27001')
  return data
}

export async function getComplianceStatus(): Promise<ComplianceStatus> {
  const { data } = await apiClient.get('/api/compliance/status')
  return data
}
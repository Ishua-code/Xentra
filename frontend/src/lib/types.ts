export type PrivilegeLevel = 'domain_admin' | 'service_account' | 'standard'

export interface Identity {
  username: string
  privilege_level: PrivilegeLevel
  mfa_enabled: boolean
  last_login_days_ago: number
  owned_asset_ip: string
}

export interface Vulnerability {
  cve_id: string
  host: string
  cvss_score: number
}

export interface UnifiedFinding {
  cve_id: string
  host: string
  owner: string
  epss_score: number
  identity_exposure_score: number
  graph_proximity_score: number
  betweenness_centrality: number
  unified_risk_score: number
  hops_to_domain_admin: number | null
  attack_path: string[] | null
}

export type TicketStatus = 'Open' | 'Investigating' | 'Resolved'
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

export interface Ticket {
  ticket_id: string
  title: string
  severity: Severity
  cve_id: string
  host: string
  owner: string
  epss_score: number
  identity_exposure_score: number
  unified_risk_score: number
  attack_path: string[] | null
  hops_to_domain_admin: number | null
  recommended_actions: string[]
  status: TicketStatus
  created_at: string
}

export interface CorrelateRequest {
  vulnerabilities: Vulnerability[]
  identities: Identity[]
}

export interface CorrelateResponse {
  findings: UnifiedFinding[]
  tickets: Ticket[]
}

export interface EpssScore {
  cve_id: string
  epss_score: number
  percentile?: number
}
import type { CorrelateRequest, CorrelateResponse, EpssScore, Identity, Ticket, UnifiedFinding } from './types'

// TEMPORARY: hardcoded to local backend. Move to an env var (NEXT_PUBLIC_API_URL)
// before deploying anywhere outside your own machine.
const API_BASE = 'http://localhost:8000/api/v1'

const TOKEN_KEY = 'xentra_token'

export function getToken(): string | null {
  if (typeof window === 'undefined') return null
  return window.localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string) {
  window.localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  window.localStorage.removeItem(TOKEN_KEY)
}

class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers as Record<string, string> | undefined),
  }

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers })

  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail ?? detail
    } catch {
      // response wasn't JSON — keep the default statusText
    }
    throw new ApiError(res.status, typeof detail === 'string' ? detail : JSON.stringify(detail))
  }

  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export async function login(username: string, password: string): Promise<string> {
  const form = new URLSearchParams()
  form.set('username', username)
  form.set('password', password)

  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  })

  if (!res.ok) {
    throw new ApiError(res.status, 'Incorrect username or password')
  }

  const data = await res.json()
  setToken(data.access_token)
  return data.access_token as string
}

export function getFindings() {
  return request<UnifiedFinding[]>('/findings')
}

export function getIdentities() {
  return request<Identity[]>('/identities')
}

export function getIdentity(username: string) {
  return request<Identity>(`/identities/${encodeURIComponent(username)}`)
}

export function getEpssScore(cveId: string) {
  return request<EpssScore>(`/epss/${encodeURIComponent(cveId)}`)
}

export function correlate(payload: CorrelateRequest) {
  return request<CorrelateResponse>('/correlate', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function getTickets(owner?: string) {
  const query = owner ? `?owner=${encodeURIComponent(owner)}` : ''
  return request<Ticket[]>(`/tickets${query}`)
}

export function updateTicketStatus(ticketId: string, status: string) {
  return request<Ticket>(`/tickets/${encodeURIComponent(ticketId)}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  })
}

export { ApiError }
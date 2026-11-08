export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message)
  }
}

let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: (() => void) | null) {
  onUnauthorized = fn
}

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(path, {
    method: opts.method || 'GET',
    credentials: 'same-origin',
    headers: opts.body !== undefined ? { 'content-type': 'application/json' } : {},
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  })
  let data: any = null
  try {
    data = await res.json()
  } catch {}
  if (!res.ok) {
    if (res.status === 401 && path.startsWith('/api/app/')) onUnauthorized?.()
    throw new ApiError(data?.error || `HTTP ${res.status}`, res.status)
  }
  return data as T
}

/** The target of a card request (see worker/util.ts): cards carry no host, the user picks one every time. */
export const CARD_TARGET = '@card'

/** A request or grant target as it reads mid-sentence: "Shared a payment card with claw". */
export function describeTarget(target: string | null): string {
  return target === CARD_TARGET ? 'a payment card' : target || ''
}

export interface Agent {
  id: string
  name: string
  fingerprint: string
  status: string
  created_at: number
  approved_at: number | null
  last_seen_at: number | null
  grants: Grant[]
  public_key?: string
}

export interface Grant {
  id: string
  agent_id: string
  host: string
  item_name: string
  created_at: number
  expires_at: number | null
  uses: number
  last_used_at: number | null
}

export interface PendingRequest {
  id: string
  agent_id: string
  agent_name: string
  fingerprint: string
  public_key: string
  host: string
  reason: string
  created_at: number
  expires_at: number
}

export interface LogEntry {
  id: number
  ts: number
  event: string
  agent_name: string | null
  host: string | null
  detail: string | null
}

export interface AppState {
  pendingAgents: Agent[]
  pendingRequests: PendingRequest[]
  agents: Agent[]
  logs: LogEntry[]
  pushSubscriptions: number
  passkeys: { id: string; name: string; created_at: number; last_used_at: number | null }[]
}

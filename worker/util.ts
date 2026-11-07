const enc = new TextEncoder()

export function b64(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let s = ''
  for (let i = 0; i < view.length; i += 0x8000) s += String.fromCharCode(...view.subarray(i, i + 0x8000))
  return btoa(s)
}

export function b64url(bytes: ArrayBuffer | Uint8Array): string {
  return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function fromB64(text: string): Uint8Array {
  const norm = text.replace(/-/g, '+').replace(/_/g, '/')
  const padded = norm + '='.repeat((4 - (norm.length % 4)) % 4)
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0))
}

export function utf8(text: string): Uint8Array {
  return enc.encode(text)
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === 'string' ? utf8(data) : data
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  return [...(await sha256(data))].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function randomToken(bytes = 32): string {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)))
}

export function randomId(): string {
  return randomToken(12)
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]
  return d === 0
}

/** Human-comparable fingerprint of an agent public key, e.g. "3F2A-91C0-77DE-0B14". */
export async function fingerprint(publicKeyB64: string): Promise<string> {
  const hex = (await sha256Hex(fromB64(publicKeyB64))).slice(0, 16).toUpperCase()
  return hex.match(/.{4}/g)!.join('-')
}

export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
  }
}

export function json(data: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  })
}

export function now(): number {
  return Date.now()
}

/**
 * Normalises whatever an agent passes as "host" (a bare host, a URL, host:port)
 * into a lowercase hostname. Returns null when nothing sensible is left.
 */
export function normalizeHost(input: string): string | null {
  let raw = String(input || '').trim().toLowerCase()
  if (!raw) return null
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(raw)) raw = `https://${raw}`
  try {
    const host = new URL(raw).hostname.replace(/\.$/, '')
    if (!host || host.length > 253 || !/^[a-z0-9.\-\[\]:_]+$/.test(host)) return null
    return host
  } catch {
    return null
  }
}

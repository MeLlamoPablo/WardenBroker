// Bitwarden client crypto, running entirely on the user's device.
//
// Implements the parts of the Bitwarden protocol WardenBroker needs: KDF
// (PBKDF2-SHA256 / Argon2id), master key stretching, EncString decryption
// (AES-256-CBC + HMAC-SHA256, and RSA-OAEP for organisation keys), password
// login and /sync. Requests go through the broker's narrow proxy because the
// Bitwarden API is not CORS-enabled for third-party origins.
import { b64, concat, equal, fromB64, td, utf8 } from './bytes'

export interface Kdf {
  kdf: number // 0 = PBKDF2-SHA256, 1 = Argon2id
  kdfIterations: number
  kdfMemory?: number | null // MiB
  kdfParallelism?: number | null
}

export interface SymKey {
  enc: Uint8Array<ArrayBuffer>
  mac: Uint8Array<ArrayBuffer>
}

export interface VaultItem {
  id: string
  type: number
  name: string
  username: string
  password: string
  totp: string
  uris: { uri: string; match: number | null }[]
  notes: string
  fields: { name: string; value: string }[]
  organization: string | null
}

// ------------------------------------------------------------------ helpers

/** Lower-cases the first letter of every key: Bitwarden servers disagree on PascalCase vs camelCase. */
export function camelize<T = any>(value: unknown): T {
  if (Array.isArray(value)) return value.map(camelize) as T
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) out[k.charAt(0).toLowerCase() + k.slice(1)] = camelize(v)
    return out as T
  }
  return value as T
}

async function pbkdf2(password: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256))
}

async function hmac(key: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data))
}

/** HKDF-Expand only (Bitwarden stretches the master key without an extract step). */
async function hkdfExpand(prk: Uint8Array<ArrayBuffer>, info: string, length: number): Promise<Uint8Array<ArrayBuffer>> {
  const out = new Uint8Array(length)
  let prev = new Uint8Array(0)
  let offset = 0
  for (let i = 1; offset < length; i++) {
    prev = await hmac(prk, concat(prev, utf8(info), new Uint8Array([i])))
    out.set(prev.subarray(0, Math.min(prev.length, length - offset)), offset)
    offset += prev.length
  }
  return out
}

// ---------------------------------------------------------------------- KDF

export async function deriveMasterKey(password: string, email: string, kdf: Kdf): Promise<Uint8Array<ArrayBuffer>> {
  const normEmail = email.trim().toLowerCase()
  if (kdf.kdf === 0) return pbkdf2(utf8(password), utf8(normEmail), kdf.kdfIterations)
  if (kdf.kdf === 1) {
    const { argon2id } = await import('hash-wasm')
    const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(normEmail)))
    const out = await argon2id({
      password: utf8(password),
      salt,
      iterations: kdf.kdfIterations,
      memorySize: (kdf.kdfMemory || 64) * 1024,
      parallelism: kdf.kdfParallelism || 4,
      hashLength: 32,
      outputType: 'binary',
    })
    return new Uint8Array(out)
  }
  throw new Error(`unsupported KDF type ${kdf.kdf}`)
}

export async function masterPasswordHash(masterKey: Uint8Array<ArrayBuffer>, password: string): Promise<string> {
  return b64(await pbkdf2(masterKey, utf8(password), 1))
}

export async function stretch(masterKey: Uint8Array<ArrayBuffer>): Promise<SymKey> {
  return { enc: await hkdfExpand(masterKey, 'enc', 32), mac: await hkdfExpand(masterKey, 'mac', 32) }
}

export function symKey(bytes: Uint8Array<ArrayBuffer>): SymKey {
  if (bytes.length !== 64) throw new Error(`expected a 64 byte key, got ${bytes.length}`)
  return { enc: bytes.slice(0, 32), mac: bytes.slice(32, 64) }
}

export function symKeyBytes(key: SymKey): Uint8Array<ArrayBuffer> {
  return concat(key.enc, key.mac)
}

// ---------------------------------------------------------------- EncString

const aesKeys = new WeakMap<Uint8Array, CryptoKey>()

async function aesKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  let k = aesKeys.get(raw)
  if (!k) {
    k = await crypto.subtle.importKey('raw', raw, 'AES-CBC', false, ['decrypt', 'encrypt'])
    aesKeys.set(raw, k)
  }
  return k
}

export async function decryptBytes(encString: string, key: SymKey | null, privateKey?: CryptoKey | null): Promise<Uint8Array<ArrayBuffer>> {
  const dot = encString.indexOf('.')
  if (dot < 1) throw new Error('malformed EncString')
  const type = Number(encString.slice(0, dot))
  const parts = encString.slice(dot + 1).split('|')
  if (type === 3 || type === 4) {
    if (!privateKey) throw new Error('RSA EncString without a private key')
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, fromB64(parts[0])))
  }
  if (!key) throw new Error('symmetric EncString without a key')
  if (type !== 0 && type !== 2) throw new Error(`unsupported EncString type ${type}`)
  const iv = fromB64(parts[0])
  const data = fromB64(parts[1])
  if (type === 2) {
    if (!parts[2]) throw new Error('missing MAC')
    if (!equal(await hmac(key.mac, concat(iv, data)), fromB64(parts[2]))) throw new Error('MAC mismatch: wrong key or tampered data')
  }
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, await aesKey(key.enc), data))
}

export async function decryptString(encString: string | null | undefined, key: SymKey | null): Promise<string> {
  if (!encString) return ''
  return td.decode(await decryptBytes(encString, key))
}

/** Used only by tests and the mock server: produce a type 2 EncString. */
export async function encryptString(plain: string | Uint8Array<ArrayBuffer>, key: SymKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, await aesKey(key.enc), typeof plain === 'string' ? utf8(plain) : plain))
  const mac = await hmac(key.mac, concat(iv, data))
  return `2.${b64(iv)}|${b64(data)}|${b64(mac)}`
}

// ------------------------------------------------------------------- vault

export interface SyncData {
  profile: {
    email: string
    key?: string
    privateKey?: string | null
    organizations?: { id: string; name: string; key?: string }[]
  }
  ciphers: any[]
}

/** Unwraps the user key from profile.key with the stretched master key. */
export async function unwrapUserKey(protectedKey: string, masterKey: Uint8Array<ArrayBuffer>): Promise<SymKey> {
  const stretched = await stretch(masterKey)
  try {
    return symKey(await decryptBytes(protectedKey, stretched))
  } catch {
    // Very old accounts encrypt the user key directly with the master key (type 0).
    return symKey(await decryptBytes(protectedKey, { enc: masterKey, mac: new Uint8Array(32) }))
  }
}

export async function decryptVault(sync: SyncData, userKey: SymKey): Promise<VaultItem[]> {
  let privateKey: CryptoKey | null = null
  if (sync.profile.privateKey) {
    const der = await decryptBytes(sync.profile.privateKey, userKey)
    privateKey = await crypto.subtle.importKey('pkcs8', der, { name: 'RSA-OAEP', hash: 'SHA-1' }, false, ['decrypt'])
  }
  const orgKeys = new Map<string, SymKey>()
  const orgNames = new Map<string, string>()
  for (const org of sync.profile.organizations || []) {
    orgNames.set(org.id, org.name)
    if (!org.key || !privateKey) continue
    try {
      const type = Number(org.key.split('.')[0])
      let pk = privateKey
      if (type === 3) {
        const der = await decryptBytes(sync.profile.privateKey!, userKey)
        pk = await crypto.subtle.importKey('pkcs8', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt'])
      }
      orgKeys.set(org.id, symKey(await decryptBytes(org.key, null, pk)))
    } catch (err) {
      console.warn('could not decrypt organization key', org.id, err)
    }
  }
  const items: VaultItem[] = []
  for (const c of sync.ciphers || []) {
    if (c.deletedDate) continue
    try {
      let key: SymKey | undefined = c.organizationId ? orgKeys.get(c.organizationId) : userKey
      if (!key) continue
      if (c.key) key = symKey(await decryptBytes(c.key, key))
      const dec = (s: string | null | undefined) => decryptString(s, key!)
      const login = c.login || {}
      items.push({
        id: c.id,
        type: c.type,
        name: await dec(c.name),
        username: await dec(login.username),
        password: await dec(login.password),
        totp: await dec(login.totp),
        uris: await Promise.all((login.uris || []).map(async (u: any) => ({ uri: await dec(u.uri), match: u.match ?? null }))),
        notes: await dec(c.notes),
        fields: await Promise.all((c.fields || []).map(async (f: any) => ({ name: await dec(f.name), value: await dec(f.value) }))),
        organization: c.organizationId ? orgNames.get(c.organizationId) || 'Organization' : null,
      })
    } catch (err) {
      console.warn('could not decrypt item', c.id, err)
    }
  }
  return items.sort((a, b) => a.name.localeCompare(b.name))
}

// ------------------------------------------------------------- host match

const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'gob', 'nic'])

export function hostOf(uri: string): string | null {
  let raw = uri.trim().toLowerCase()
  if (!raw) return null
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(raw)) raw = `https://${raw}`
  try {
    const h = new URL(raw).hostname.replace(/\.$/, '')
    return h || null
  } catch {
    return null
  }
}

export function baseDomain(host: string): string {
  if (/^[\d.]+$/.test(host) || host.includes(':')) return host
  const labels = host.split('.')
  if (labels.length <= 2) return host
  const n = labels.length
  if (labels[n - 1].length === 2 && SECOND_LEVEL.has(labels[n - 2])) return labels.slice(-3).join('.')
  return labels.slice(-2).join('.')
}

/** 2 = exact host, 1 = same registrable domain, 0 = no match. Honours Bitwarden's URI match types. */
export function matchScore(item: VaultItem, host: string): number {
  let best = 0
  for (const { uri, match } of item.uris) {
    if (match === 5) continue // never
    if (match === 4) {
      try {
        if (new RegExp(uri, 'i').test(`https://${host}/`)) best = Math.max(best, 2)
      } catch {}
      continue
    }
    const h = hostOf(uri)
    if (!h) continue
    if (h === host) best = Math.max(best, 2)
    else if ((match === null || match === 0) && baseDomain(h) === baseDomain(host)) best = Math.max(best, 1)
  }
  return best
}

export function candidatesFor(items: VaultItem[], host: string): { items: VaultItem[]; autoPick: VaultItem | null } {
  const scored = items.map((item) => ({ item, score: matchScore(item, host) })).filter((s) => s.score > 0)
  const top = Math.max(0, ...scored.map((s) => s.score))
  const best = scored.filter((s) => s.score === top).map((s) => s.item)
  const all = [...best, ...scored.filter((s) => s.score !== top).map((s) => s.item)]
  return { items: all, autoPick: best.length === 1 ? best[0] : null }
}

// ------------------------------------------------------------------ network

export class BwError extends Error {
  constructor(
    message: string,
    public status: number,
    public body: any,
  ) {
    super(message)
  }
}

async function post(path: string, body: unknown): Promise<any> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  })
  const text = await res.text()
  let data: any = null
  try {
    data = camelize(JSON.parse(text))
  } catch {}
  if (!res.ok) {
    const message =
      data?.errorModel?.message || data?.error_description || data?.errorDescription || data?.message || data?.error || `HTTP ${res.status}`
    throw new BwError(String(message), res.status, data)
  }
  return data
}

export async function prelogin(email: string): Promise<Kdf> {
  return post('/api/bw/prelogin', { email })
}

export interface TokenResponse {
  accessToken: string
  refreshToken: string
  expiresIn: number
  key?: string
  privateKey?: string
  twoFactorToken?: string
}

function toToken(data: any): TokenResponse {
  return {
    accessToken: data.access_token ?? data.accessToken,
    refreshToken: data.refresh_token ?? data.refreshToken,
    expiresIn: data.expires_in ?? data.expiresIn,
    key: data.key,
    privateKey: data.privateKey,
    twoFactorToken: data.twoFactorToken,
  }
}

export interface LoginChallenge {
  kind: 'two-factor' | 'new-device'
  providers?: number[]
}

/** Classifies a failed password grant into something the UI can ask for. */
export function loginChallenge(err: unknown): LoginChallenge | null {
  if (!(err instanceof BwError)) return null
  const body = err.body || {}
  const providers = body.twoFactorProviders2 || body.twoFactorProviders
  if (providers) {
    const ids = Array.isArray(providers) ? providers.map(Number) : Object.keys(providers).map(Number)
    return { kind: 'two-factor', providers: ids }
  }
  if (/new device/i.test(err.message)) return { kind: 'new-device' }
  return null
}

export function deviceId(): string {
  let id = localStorage.getItem('wb.deviceId')
  if (!id) {
    id = crypto.randomUUID()
    localStorage.setItem('wb.deviceId', id)
  }
  return id
}

export async function passwordLogin(
  email: string,
  hash: string,
  extra: Record<string, string> = {},
): Promise<TokenResponse> {
  const remember = localStorage.getItem(`wb.2fa.${email.toLowerCase()}`)
  const fields: Record<string, string> = {
    grant_type: 'password',
    username: email.trim().toLowerCase(),
    password: hash,
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '14',
    deviceIdentifier: deviceId(),
    deviceName: 'WardenBroker',
    ...(remember && !extra.twoFactorToken ? { twoFactorToken: remember, twoFactorProvider: '5', twoFactorRemember: '0' } : {}),
    ...extra,
  }
  try {
    const res = toToken(await post('/api/bw/token', { fields }))
    if (res.twoFactorToken) localStorage.setItem(`wb.2fa.${email.toLowerCase()}`, res.twoFactorToken)
    return res
  } catch (err) {
    // A stale "remember this device" token: drop it and let the user enter a code.
    if (remember && !extra.twoFactorToken && loginChallenge(err)?.kind === 'two-factor') {
      localStorage.removeItem(`wb.2fa.${email.toLowerCase()}`)
    }
    throw err
  }
}

export async function sendEmailCode(email: string, hash: string): Promise<void> {
  await post('/api/bw/send-email-login', { email, masterPasswordHash: hash, deviceIdentifier: deviceId() })
}

export async function refresh(refreshToken: string): Promise<TokenResponse> {
  return toToken(await post('/api/bw/token', { fields: { grant_type: 'refresh_token', client_id: 'web', refresh_token: refreshToken } }))
}

export async function sync(accessToken: string): Promise<SyncData> {
  const res = await fetch('/api/bw/sync', { headers: { authorization: `Bearer ${accessToken}` }, credentials: 'same-origin' })
  if (!res.ok) throw new BwError(`sync failed (HTTP ${res.status})`, res.status, null)
  return camelize(await res.json())
}

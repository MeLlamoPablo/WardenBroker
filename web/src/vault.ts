// Device-side vault session: login, passkey lock, local cache and refresh.
import * as bw from './bw'
import { b64, fromB64, td, utf8 } from './bytes'
import { passkeyLogin, passkeyRegister } from './passkey'

export interface Session {
  email: string
  userKey: bw.SymKey
  items: bw.VaultItem[]
  refreshToken: string | null
  lockKey: CryptoKey | null
  credentialId: string | null
  syncedAt: number | null
  syncError: string | null
}

interface LockBlob {
  v: 1
  email: string
  credentialId: string
  iv: string
  ct: string
}

interface LockedSecrets {
  userKey: string
  refreshToken: string | null
}

const LOCK = 'wb.lock'
const EMAIL = 'wb.email'

export class PrfUnsupportedError extends Error {
  constructor() {
    super("This device's passkeys can't unlock the vault (no WebAuthn PRF support). You'll unlock with your master password instead.")
  }
}

// ------------------------------------------------------------ local storage

export function rememberedEmail(): string {
  return localStorage.getItem(EMAIL) || ''
}

export function lockBlob(): LockBlob | null {
  try {
    const raw = localStorage.getItem(LOCK)
    return raw ? (JSON.parse(raw) as LockBlob) : null
  } catch {
    return null
  }
}

export function forgetDevice() {
  localStorage.removeItem(LOCK)
  void idb('delete')
}

async function lockKeyFromPrf(prf: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8('wardenbroker/v1 device lock') },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function writeLock(s: Session) {
  if (!s.lockKey || !s.credentialId) return
  const secrets: LockedSecrets = { userKey: b64(bw.symKeyBytes(s.userKey)), refreshToken: s.refreshToken }
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, s.lockKey, utf8(JSON.stringify(secrets)))
  const blob: LockBlob = { v: 1, email: s.email, credentialId: s.credentialId, iv: b64(iv), ct: b64(ct) }
  localStorage.setItem(LOCK, JSON.stringify(blob))
}

// The encrypted /sync response is cached so unlocking works instantly (and even
// when the Bitwarden server is slow). It is Bitwarden ciphertext, exactly what
// official clients keep on disk.
function idb(op: 'get' | 'put' | 'delete', value?: unknown): Promise<any> {
  return new Promise((resolve) => {
    const open = indexedDB.open('wardenbroker', 1)
    open.onupgradeneeded = () => open.result.createObjectStore('kv')
    open.onerror = () => resolve(null)
    open.onsuccess = () => {
      const tx = open.result.transaction('kv', op === 'get' ? 'readonly' : 'readwrite')
      const store = tx.objectStore('kv')
      const req = op === 'get' ? store.get('sync') : op === 'put' ? store.put(value, 'sync') : store.delete('sync')
      req.onsuccess = () => resolve(req.result ?? null)
      req.onerror = () => resolve(null)
    }
  })
}

// ------------------------------------------------------------------- login

export interface PreparedLogin {
  email: string
  masterKey: Uint8Array<ArrayBuffer>
  hash: string
}

export async function prepareLogin(email: string, password: string): Promise<PreparedLogin> {
  const norm = email.trim().toLowerCase()
  const kdf = await bw.prelogin(norm)
  const masterKey = await bw.deriveMasterKey(password, norm, kdf)
  return { email: norm, masterKey, hash: await bw.masterPasswordHash(masterKey, password) }
}

/** Completes a master password login. Throws BwError (see bw.loginChallenge) when 2FA / new-device OTP is needed. */
export async function completeLogin(prep: PreparedLogin, extra: Record<string, string> = {}): Promise<Session> {
  const token = await bw.passwordLogin(prep.email, prep.hash, extra)
  const data = await bw.sync(token.accessToken)
  const protectedKey = data.profile.key || token.key
  if (!protectedKey) throw new Error('The Bitwarden server did not return an encrypted user key')
  const userKey = await bw.unwrapUserKey(protectedKey, prep.masterKey)
  const items = await bw.decryptVault(data, userKey)
  await idb('put', data)
  localStorage.setItem(EMAIL, prep.email)
  const previous = lockBlob()
  if (previous && previous.email !== prep.email) forgetDevice()
  return {
    email: prep.email,
    userKey,
    items,
    refreshToken: token.refreshToken,
    lockKey: null,
    credentialId: null,
    syncedAt: Date.now(),
    syncError: null,
  }
}

/** Binds the session to a passkey: registers one (or reuses this device's) and stores the vault key under its PRF. */
export async function enablePasskey(s: Session): Promise<void> {
  let result
  try {
    result = await passkeyRegister()
  } catch (err) {
    // A passkey for this broker already lives on this authenticator: just use it.
    if ((err as Error).name !== 'InvalidStateError') throw err
    result = await passkeyLogin()
  }
  if (!result.prf) result = await passkeyLogin(result.credentialId)
  if (!result.prf) throw new PrfUnsupportedError()
  s.lockKey = await lockKeyFromPrf(result.prf)
  s.credentialId = result.credentialId
  await writeLock(s)
}

export async function unlockWithPasskey(): Promise<Session> {
  const blob = lockBlob()
  if (!blob) throw new Error('No passkey is set up on this device')
  const { credentialId, prf } = await passkeyLogin(blob.credentialId)
  if (!prf) throw new PrfUnsupportedError()
  const lockKey = await lockKeyFromPrf(prf)
  let secrets: LockedSecrets
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(blob.iv) }, lockKey, fromB64(blob.ct))
    secrets = JSON.parse(td.decode(plain))
  } catch {
    throw new Error('That passkey cannot unlock this device. Sign in with your master password.')
  }
  const userKey = bw.symKey(fromB64(secrets.userKey))
  const cached = await idb('get')
  const items = cached ? await bw.decryptVault(cached, userKey) : []
  return {
    email: blob.email,
    userKey,
    items,
    refreshToken: secrets.refreshToken,
    lockKey,
    credentialId,
    syncedAt: null,
    syncError: null,
  }
}

/** Pulls a fresh copy of the vault with the stored refresh token. */
export async function refreshVault(s: Session): Promise<void> {
  if (!s.refreshToken) return
  try {
    const token = await bw.refresh(s.refreshToken)
    const data = await bw.sync(token.accessToken)
    s.items = await bw.decryptVault(data, s.userKey)
    await idb('put', data)
    if (token.refreshToken && token.refreshToken !== s.refreshToken) {
      s.refreshToken = token.refreshToken
      await writeLock(s)
    }
    s.syncedAt = Date.now()
    s.syncError = null
  } catch (err) {
    s.syncError = (err as Error).message
    if (err instanceof bw.BwError && (err.status === 400 || err.status === 401)) {
      s.syncError = 'Bitwarden session expired: sign in with your master password to refresh the vault.'
    }
  }
}

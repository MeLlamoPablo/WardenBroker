// Web Push with encrypted payloads (RFC 8291, aes128gcm) and VAPID (RFC 8292),
// using only WebCrypto so it runs on Workers with a few hundred µs of CPU.
import { b64url, concat, fromB64, utf8 } from './util'

export interface PushSubscriptionRecord {
  endpoint: string
  p256dh: string
  auth: string
}

export interface VapidKeys {
  publicKey: string // base64url, uncompressed P-256 point
  privateJwk: JsonWebKey
}

export async function generateVapidKeys(): Promise<VapidKeys> {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const raw = (await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer
  const privateJwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey
  return { publicKey: b64url(raw), privateJwk }
}

const jwtCache = new Map<string, { header: string; exp: number }>()

export async function vapidHeader(endpoint: string, keys: VapidKeys, subject: string): Promise<string> {
  const aud = new URL(endpoint).origin
  const nowS = Math.floor(Date.now() / 1000)
  const cached = jwtCache.get(aud)
  if (cached && cached.exp - nowS > 3600) return cached.header
  const exp = nowS + 12 * 3600
  const enc = (o: unknown) => b64url(utf8(JSON.stringify(o)))
  const unsigned = `${enc({ typ: 'JWT', alg: 'ES256' })}.${enc({ aud, exp, sub: subject })}`
  const key = await crypto.subtle.importKey('jwk', keys.privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, utf8(unsigned))
  const header = `vapid t=${unsigned}.${b64url(sig)}, k=${keys.publicKey}`
  jwtCache.set(aud, { header, exp })
  return header
}

async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, length * 8))
}

/** Encrypts a push message body for one subscription (RFC 8291). */
export async function encryptPayload(payload: Uint8Array, sub: PushSubscriptionRecord): Promise<Uint8Array> {
  const uaPublic = fromB64(sub.p256dh)
  const authSecret = fromB64(sub.auth)
  const local = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair
  const asPublic = new Uint8Array((await crypto.subtle.exportKey('raw', local.publicKey)) as ArrayBuffer)
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey } as unknown as SubtleCryptoDeriveKeyAlgorithm, local.privateKey, 256))
  const keyInfo = concat(utf8('WebPush: info\0'), uaPublic, asPublic)
  const ikm = await hkdf(authSecret, ecdhSecret, keyInfo, 32)
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const cek = await hkdf(salt, ikm, utf8('Content-Encoding: aes128gcm\0'), 16)
  const nonce = await hkdf(salt, ikm, utf8('Content-Encoding: nonce\0'), 12)
  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt'])
  const record = concat(payload, new Uint8Array([2]))
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, record))
  const header = new Uint8Array(16 + 4 + 1 + asPublic.length)
  header.set(salt, 0)
  new DataView(header.buffer).setUint32(16, 4096)
  header[20] = asPublic.length
  header.set(asPublic, 21)
  return concat(header, ciphertext)
}

/** Sends one push. Returns the push service status (404/410 mean "subscription gone"). */
export async function sendPush(sub: PushSubscriptionRecord, message: unknown, keys: VapidKeys, subject: string): Promise<number> {
  const body = await encryptPayload(utf8(JSON.stringify(message)), sub)
  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      authorization: await vapidHeader(sub.endpoint, keys, subject),
      'content-encoding': 'aes128gcm',
      'content-type': 'application/octet-stream',
      ttl: '600',
      urgency: 'high',
    },
    body,
  })
  return res.status
}

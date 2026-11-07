// Minimal WebAuthn relying-party verification for a single-user broker.
//
// Registration trusts the browser's `getPublicKey()` (SPKI) instead of parsing
// the CBOR attestation object: the ceremony only runs inside an already
// authenticated session, so attestation adds nothing for us. Assertions are
// verified fully: challenge, origin, RP ID hash, user presence + verification
// and the signature over authenticatorData || SHA-256(clientDataJSON).
import { concat, equalBytes, fromB64, HttpError, sha256 } from './util'

export const ALG_ES256 = -7
export const ALG_EDDSA = -8
export const ALG_RS256 = -257
export const SUPPORTED_ALGS = [ALG_ES256, ALG_EDDSA, ALG_RS256]

interface ClientData {
  type: string
  challenge: string
  origin: string
  crossOrigin?: boolean
}

export function parseClientData(clientDataJSON: Uint8Array): ClientData {
  try {
    return JSON.parse(new TextDecoder().decode(clientDataJSON))
  } catch {
    throw new HttpError(400, 'invalid clientDataJSON')
  }
}

export function checkClientData(cd: ClientData, type: string, challenge: string, origin: string) {
  if (cd.type !== type) throw new HttpError(400, 'unexpected WebAuthn ceremony type')
  if (cd.challenge !== challenge) throw new HttpError(400, 'challenge mismatch')
  if (cd.origin !== origin) throw new HttpError(400, 'origin mismatch')
  if (cd.crossOrigin) throw new HttpError(400, 'cross-origin WebAuthn is not allowed')
}

/** Converts an ASN.1 DER ECDSA signature into the raw r||s form WebCrypto wants. */
export function derToRaw(der: Uint8Array, size = 32): Uint8Array {
  if (der[0] !== 0x30) throw new HttpError(400, 'bad ECDSA signature')
  let offset = 2
  if (der[1] & 0x80) offset = 2 + (der[1] & 0x7f)
  const readInt = () => {
    if (der[offset] !== 0x02) throw new HttpError(400, 'bad ECDSA signature')
    const len = der[offset + 1]
    let value = der.subarray(offset + 2, offset + 2 + len)
    offset += 2 + len
    while (value.length > size && value[0] === 0) value = value.subarray(1)
    if (value.length > size) throw new HttpError(400, 'bad ECDSA signature')
    const out = new Uint8Array(size)
    out.set(value, size - value.length)
    return out
  }
  return concat(readInt(), readInt())
}

async function verifySignature(alg: number, spki: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  if (alg === ALG_ES256) {
    const key = await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
    return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derToRaw(signature), data)
  }
  if (alg === ALG_RS256) {
    const key = await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data)
  }
  if (alg === ALG_EDDSA) {
    const key = await crypto.subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify'])
    return crypto.subtle.verify('Ed25519', key, signature, data)
  }
  throw new HttpError(400, 'unsupported passkey algorithm')
}

export interface AssertionInput {
  authenticatorData: string
  clientDataJSON: string
  signature: string
}

export interface StoredPasskey {
  publicKey: string
  alg: number
  signCount: number
}

/** Verifies a WebAuthn assertion and returns the authenticator's new sign counter. */
export async function verifyAssertion(
  input: AssertionInput,
  passkey: StoredPasskey,
  expected: { challenge: string; origin: string; rpId: string },
): Promise<number> {
  const authData = fromB64(input.authenticatorData)
  const clientDataJSON = fromB64(input.clientDataJSON)
  checkClientData(parseClientData(clientDataJSON), 'webauthn.get', expected.challenge, expected.origin)
  if (authData.length < 37) throw new HttpError(400, 'authenticatorData too short')
  if (!equalBytes(authData.subarray(0, 32), await sha256(expected.rpId))) throw new HttpError(400, 'RP ID mismatch')
  const flags = authData[32]
  if (!(flags & 0x01)) throw new HttpError(400, 'user presence required')
  if (!(flags & 0x04)) throw new HttpError(400, 'user verification required')
  const counter = new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0)
  const signed = concat(authData, await sha256(clientDataJSON))
  const ok = await verifySignature(passkey.alg, fromB64(passkey.publicKey), fromB64(input.signature), signed)
  if (!ok) throw new HttpError(401, 'invalid passkey signature')
  // Synced passkeys always report 0; only enforce monotonicity when both sides count.
  if (counter !== 0 || passkey.signCount !== 0) {
    if (counter <= passkey.signCount) throw new HttpError(401, 'passkey counter did not increase (cloned authenticator?)')
  }
  return counter
}

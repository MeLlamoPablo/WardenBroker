// Passkeys do two jobs in WardenBroker:
//  1. authenticate the user to the broker (assertion verified server-side), and
//  2. through the WebAuthn PRF extension, produce a 32-byte secret that only
//     this passkey can reproduce. That secret encrypts the Bitwarden vault key
//     on the device, so unlocking is one Face ID / fingerprint prompt.
import { b64url, fromB64, utf8 } from './bytes'
import { api } from './api'

const PRF_SALT = utf8('wardenbroker/v1 vault-unlock prf')

export function passkeysAvailable(): boolean {
  return typeof window.PublicKeyCredential !== 'undefined' && !!navigator.credentials
}

export interface PasskeyResult {
  credentialId: string
  prf: Uint8Array<ArrayBuffer> | null
}

function prfFrom(cred: PublicKeyCredential): Uint8Array<ArrayBuffer> | null {
  const ext = cred.getClientExtensionResults() as any
  const first = ext?.prf?.results?.first
  return first ? new Uint8Array(first as ArrayBuffer) : null
}

/** Signs in to the broker with a passkey, returning the PRF output when the authenticator supports it. */
export async function passkeyLogin(preferredId?: string | null): Promise<PasskeyResult> {
  const opts = await api<{ challenge: string; allowCredentials: string[] }>('/api/auth/passkey/options', { method: 'POST', body: {} })
  const ids = preferredId && opts.allowCredentials.includes(preferredId) ? [preferredId] : opts.allowCredentials
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: fromB64(opts.challenge),
      allowCredentials: ids.map((id) => ({ type: 'public-key' as const, id: fromB64(id) })),
      userVerification: 'required',
      timeout: 120000,
      extensions: { prf: { eval: { first: PRF_SALT } } } as any,
    },
  })) as PublicKeyCredential | null
  if (!cred) throw new Error('No passkey was used')
  const res = cred.response as AuthenticatorAssertionResponse
  await api('/api/auth/passkey/login', {
    method: 'POST',
    body: {
      id: cred.id,
      authenticatorData: b64url(res.authenticatorData),
      clientDataJSON: b64url(res.clientDataJSON),
      signature: b64url(res.signature),
    },
  })
  return { credentialId: cred.id, prf: prfFrom(cred) }
}

/** Creates a passkey for this broker (requires an existing session). */
export async function passkeyRegister(): Promise<PasskeyResult> {
  const opts = await api<{
    challenge: string
    rp: { id: string; name: string }
    user: { id: string; name: string; displayName: string }
    excludeCredentials: string[]
    algorithms: number[]
  }>('/api/auth/passkey/register-options', { method: 'POST', body: {} })
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: fromB64(opts.challenge),
      rp: opts.rp,
      user: { id: utf8(opts.user.id), name: opts.user.name, displayName: opts.user.displayName },
      pubKeyCredParams: opts.algorithms.map((alg) => ({ type: 'public-key' as const, alg })),
      excludeCredentials: opts.excludeCredentials.map((id) => ({ type: 'public-key' as const, id: fromB64(id) })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      timeout: 120000,
      extensions: { prf: { eval: { first: PRF_SALT } } } as any,
    },
  })) as PublicKeyCredential | null
  if (!cred) throw new Error('No passkey was created')
  const res = cred.response as AuthenticatorAttestationResponse
  const publicKey = res.getPublicKey()
  if (!publicKey) throw new Error('This authenticator did not expose its public key')
  await api('/api/auth/passkey/register', {
    method: 'POST',
    body: {
      id: cred.id,
      clientDataJSON: b64url(res.clientDataJSON),
      publicKey: b64url(publicKey),
      alg: res.getPublicKeyAlgorithm(),
      name: guessDeviceName(),
    },
  })
  return { credentialId: cred.id, prf: prfFrom(cred) }
}

function guessDeviceName(): string {
  const ua = navigator.userAgent
  if (/iPhone/.test(ua)) return 'iPhone'
  if (/iPad/.test(ua)) return 'iPad'
  if (/Android/.test(ua)) return 'Android'
  if (/Mac/.test(ua)) return 'Mac'
  if (/Windows/.test(ua)) return 'Windows'
  return 'Passkey'
}

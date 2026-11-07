// End-to-end encryption from the phone to one agent.
//
// ECIES over P-256: an ephemeral ECDH key agrees a secret with the agent's
// registered public key, HKDF-SHA256 turns it into an AES-256-GCM key, and the
// requested host is bound in as associated data so the broker cannot replay a
// secret approved for one host as the answer for another.
//
// Wire format (base64url): 0x01 || ephemeral public key (65) || nonce (12) || ciphertext+tag
import { b64url, concat, fromB64, utf8 } from './bytes'

export const SEAL_VERSION = 1

export async function seal(agentPublicKeyB64: string, host: string, plaintext: Uint8Array<ArrayBuffer>): Promise<string> {
  const agentRaw = fromB64(agentPublicKeyB64)
  const agentKey = await crypto.subtle.importKey('raw', agentRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const eph = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair
  const ephRaw = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey))
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: agentKey }, eph.privateKey, 256)
  const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: concat(ephRaw, agentRaw), info: utf8('wardenbroker/v1 seal') },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  )
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: utf8(`wardenbroker/v1|${host}`) }, key, plaintext))
  return b64url(concat(new Uint8Array([SEAL_VERSION]), ephRaw, nonce, ct))
}

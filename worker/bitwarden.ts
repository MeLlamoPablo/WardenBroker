// A deliberately narrow proxy to the owner's Bitwarden-compatible server
// (bitwarden.com, bitwarden.eu, Vaultwarden, NodeWarden, ...).
//
// Bitwarden's API is not CORS-enabled for arbitrary origins, so the PWA talks
// to it through the broker. Everything that crosses this proxy is either
// ciphertext (the vault) or an authentication hash derived with PBKDF2/Argon2
// from the master password: the master password and the vault keys never
// leave the phone.
import { b64url, HttpError, utf8 } from './util'
import type { Env } from './broker'

export const BW_CLIENT_VERSION = '2025.10.0'

export function bwUrls(env: Env): { identity: string; api: string } {
  const server = (env.BW_SERVER || 'https://vault.bitwarden.com').replace(/\/+$/, '')
  let identity = `${server}/identity`
  let api = `${server}/api`
  const host = new URL(server).hostname
  if (host === 'vault.bitwarden.com' || host === 'bitwarden.com') {
    identity = 'https://identity.bitwarden.com'
    api = 'https://api.bitwarden.com'
  } else if (host === 'vault.bitwarden.eu' || host === 'bitwarden.eu') {
    identity = 'https://identity.bitwarden.eu'
    api = 'https://api.bitwarden.eu'
  }
  return {
    identity: (env.BW_IDENTITY_URL || identity).replace(/\/+$/, ''),
    api: (env.BW_API_URL || api).replace(/\/+$/, ''),
  }
}

type Kind = 'prelogin' | 'token' | 'send-email-login' | 'sync'

export async function bwProxy(env: Env, kind: Kind, payload: unknown, authorization?: string): Promise<Response> {
  const { identity, api } = bwUrls(env)
  const headers: Record<string, string> = {
    accept: 'application/json',
    'bitwarden-client-name': 'web',
    'bitwarden-client-version': BW_CLIENT_VERSION,
  }
  let url: string
  let init: RequestInit
  switch (kind) {
    case 'prelogin':
      url = `${identity}/accounts/prelogin`
      init = { method: 'POST', body: JSON.stringify(payload) }
      headers['content-type'] = 'application/json'
      break
    case 'send-email-login':
      url = `${api}/two-factor/send-email-login`
      init = { method: 'POST', body: JSON.stringify(payload) }
      headers['content-type'] = 'application/json'
      break
    case 'token': {
      const fields: Record<string, string> = {}
      for (const [k, v] of Object.entries(payload as Record<string, unknown>)) {
        if (typeof v === 'string' || typeof v === 'number') fields[k] = String(v)
      }
      url = `${identity}/connect/token`
      init = { method: 'POST', body: new URLSearchParams(fields).toString() }
      headers['content-type'] = 'application/x-www-form-urlencoded; charset=utf-8'
      if (fields.deviceType) headers['device-type'] = fields.deviceType
      if (fields.grant_type === 'password' && fields.username) headers['auth-email'] = b64url(utf8(fields.username))
      break
    }
    case 'sync':
      url = `${api}/sync?excludeDomains=true`
      init = { method: 'GET' }
      headers.authorization = authorization!
      break
  }
  let res: Response
  try {
    res = await fetch(url, { ...init, headers, redirect: 'manual' })
  } catch (err) {
    throw new HttpError(502, `could not reach the Bitwarden server: ${(err as Error).message}`)
  }
  return new Response(res.body, {
    status: res.status,
    headers: {
      'content-type': res.headers.get('content-type') || 'application/json',
      'cache-control': 'no-store',
    },
  })
}

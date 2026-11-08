// The whole broker lives in one SQLite-backed Durable Object: a single user
// means a single instance, which gives us strongly consistent storage and an
// in-memory place to park long-polling agents until the user answers.
import { DurableObject } from 'cloudflare:workers'
import { bwProxy } from './bitwarden'
import {
  CARD_TARGET,
  describeTarget,
  fingerprint,
  fromB64,
  HttpError,
  json,
  normalizeHost,
  now,
  randomId,
  randomToken,
  sha256Hex,
} from './util'
import { checkClientData, parseClientData, SUPPORTED_ALGS, verifyAssertion } from './webauthn'
import { generateVapidKeys, sendPush, type PushSubscriptionRecord, type VapidKeys } from './webpush'

export interface Env {
  BROKER: DurableObjectNamespace<Broker>
  ASSETS: Fetcher
  OWNER_EMAIL: string
  BW_SERVER?: string
  BW_IDENTITY_URL?: string
  BW_API_URL?: string
  VAPID_SUBJECT?: string
  /** Tests only: accept http:// push endpoints. Never set this in production. */
  DEV_ALLOW_INSECURE_PUSH?: string
}

const SESSION_TTL = 12 * 3600 * 1000
const CHALLENGE_TTL = 5 * 60 * 1000
const REQUEST_TTL = 10 * 60 * 1000
const MAX_WAIT_S = 25
const MAX_PENDING_AGENTS = 10
const MAX_REGISTRATIONS_PER_HOUR = 20
const MAX_PENDING_REQUESTS_PER_AGENT = 5
const MAX_LOGS = 1000
const MAX_CIPHERTEXT = 64 * 1024
const MAX_BODY = 256 * 1024
const SESSION_COOKIE = 'wb_session'

type Row = Record<string, SqlStorageValue>

interface Ctx {
  req: Request
  url: URL
  params: string[]
}

type Handler = (c: Ctx) => Promise<Response>

export class Broker extends DurableObject<Env> {
  private sql: SqlStorage
  private waiters = new Map<string, Set<() => void>>()
  private routes: [string, RegExp, Handler][] = []

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env)
    this.sql = ctx.storage.sql
    this.migrate()
    this.registerRoutes()
  }

  // ---------------------------------------------------------------- storage

  private migrate() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, method TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS challenges (challenge TEXT PRIMARY KEY, purpose TEXT NOT NULL, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS passkeys (id TEXT PRIMARY KEY, public_key TEXT NOT NULL, alg INTEGER NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER);
      CREATE TABLE IF NOT EXISTS push_subscriptions (endpoint TEXT PRIMARY KEY, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, name TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, status TEXT NOT NULL, created_at INTEGER NOT NULL, approved_at INTEGER, last_seen_at INTEGER);
      CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, host TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL, ciphertext TEXT, item_name TEXT, duration INTEGER, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, resolved_at INTEGER);
      CREATE INDEX IF NOT EXISTS requests_agent ON requests(agent_id, status);
      CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, host TEXT NOT NULL, ciphertext TEXT NOT NULL, item_name TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER, uses INTEGER NOT NULL DEFAULT 0, last_used_at INTEGER);
      CREATE UNIQUE INDEX IF NOT EXISTS grants_agent_host ON grants(agent_id, host);
      CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, event TEXT NOT NULL, agent_id TEXT, agent_name TEXT, host TEXT, detail TEXT);
    `)
  }

  private rows(query: string, ...args: SqlStorageValue[]): Row[] {
    return this.sql.exec(query, ...args).toArray() as Row[]
  }

  private row(query: string, ...args: SqlStorageValue[]): Row | undefined {
    return this.rows(query, ...args)[0]
  }

  private run(query: string, ...args: SqlStorageValue[]) {
    this.sql.exec(query, ...args)
  }

  private kvGet(key: string): string | undefined {
    return this.row('SELECT value FROM kv WHERE key = ?', key)?.value as string | undefined
  }

  private kvSet(key: string, value: string) {
    this.run('INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', key, value)
  }

  /** Cheap housekeeping on every request instead of a cron/alarm. */
  private sweep() {
    const t = now()
    this.run('DELETE FROM sessions WHERE expires_at < ?', t)
    this.run('DELETE FROM challenges WHERE expires_at < ?', t)
    this.run('DELETE FROM grants WHERE expires_at IS NOT NULL AND expires_at < ?', t)
    const expired = this.rows("SELECT id FROM requests WHERE status = 'pending' AND expires_at < ?", t)
    if (expired.length) {
      this.run("UPDATE requests SET status = 'expired', resolved_at = ? WHERE status = 'pending' AND expires_at < ?", t, t)
      for (const r of expired) this.wake(`req:${r.id}`)
    }
    // Answered requests keep no ciphertext longer than an hour, delivered or not.
    this.run("UPDATE requests SET ciphertext = NULL WHERE ciphertext IS NOT NULL AND resolved_at < ?", t - 3600 * 1000)
    this.run("DELETE FROM requests WHERE status != 'pending' AND resolved_at < ?", t - 7 * 24 * 3600 * 1000)
  }

  private log(event: string, opts: { agentId?: string | null; agentName?: string | null; host?: string | null; detail?: string | null } = {}) {
    this.run(
      'INSERT INTO logs (ts, event, agent_id, agent_name, host, detail) VALUES (?, ?, ?, ?, ?, ?)',
      now(),
      event,
      opts.agentId ?? null,
      opts.agentName ?? null,
      opts.host ?? null,
      opts.detail ?? null,
    )
    this.run('DELETE FROM logs WHERE id <= (SELECT MAX(id) FROM logs) - ?', MAX_LOGS)
  }

  // ------------------------------------------------------------ long polling

  private wait(key: string, seconds: number): Promise<void> {
    const ms = Math.max(0, Math.min(MAX_WAIT_S, seconds)) * 1000
    if (!ms) return Promise.resolve()
    return new Promise((resolve) => {
      let set = this.waiters.get(key)
      if (!set) this.waiters.set(key, (set = new Set()))
      const done = () => {
        clearTimeout(timer)
        set!.delete(done)
        if (!set!.size) this.waiters.delete(key)
        resolve()
      }
      const timer = setTimeout(done, ms)
      set.add(done)
    })
  }

  private wake(key: string) {
    for (const fn of [...(this.waiters.get(key) ?? [])]) fn()
  }

  // ------------------------------------------------------------------ http

  private route(method: string, pattern: string, handler: Handler) {
    const re = new RegExp('^' + pattern.replace(/:[a-z]+/g, '([A-Za-z0-9_-]+)') + '$')
    this.routes.push([method, re, handler.bind(this)])
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url)
    try {
      this.sweep()
      for (const [method, re, handler] of this.routes) {
        if (method !== req.method) continue
        const m = re.exec(url.pathname)
        if (m) return await handler({ req, url, params: m.slice(1) })
      }
      return json({ error: 'not found' }, 404)
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.message }, err.status)
      console.error(err)
      return json({ error: 'internal error' }, 500)
    }
  }

  private async body<T = Record<string, unknown>>(req: Request): Promise<T> {
    const len = Number(req.headers.get('content-length') || 0)
    if (len > MAX_BODY) throw new HttpError(413, 'body too large')
    const text = await req.text()
    if (text.length > MAX_BODY) throw new HttpError(413, 'body too large')
    try {
      const parsed = JSON.parse(text || '{}')
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error()
      return parsed as T
    } catch {
      throw new HttpError(400, 'expected a JSON object')
    }
  }

  private ownerEmail(): string {
    const email = (this.env.OWNER_EMAIL || '').trim().toLowerCase()
    if (!email) throw new HttpError(500, 'OWNER_EMAIL is not configured on the broker')
    return email
  }

  /** Browser-facing mutations must come from our own origin (CSRF defence in depth on top of SameSite=Strict). */
  private checkOrigin(c: Ctx) {
    const origin = c.req.headers.get('origin')
    if (origin !== c.url.origin) throw new HttpError(403, 'cross-origin request refused')
  }

  private async session(c: Ctx): Promise<void> {
    const cookie = c.req.headers.get('cookie') || ''
    const token = cookie.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`))?.[1]
    if (!token) throw new HttpError(401, 'not signed in')
    const found = this.row('SELECT expires_at FROM sessions WHERE token_hash = ?', await sha256Hex(token))
    if (!found || (found.expires_at as number) < now()) throw new HttpError(401, 'session expired')
    if (c.req.method !== 'GET') this.checkOrigin(c)
  }

  private async newSession(method: string): Promise<string> {
    const token = randomToken()
    const t = now()
    this.run('INSERT INTO sessions (token_hash, created_at, expires_at, method) VALUES (?, ?, ?, ?)', await sha256Hex(token), t, t + SESSION_TTL, method)
    return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL / 1000}`
  }

  private async agent(c: Ctx, allowPending = false): Promise<Row> {
    const token = c.req.headers.get('authorization')?.match(/^Bearer\s+(\S+)$/i)?.[1]
    if (!token) throw new HttpError(401, 'missing agent token')
    const agent = this.row('SELECT * FROM agents WHERE token_hash = ?', await sha256Hex(token))
    if (!agent) throw new HttpError(401, 'unknown agent token')
    if (agent.status === 'revoked') throw new HttpError(403, 'this agent was denied or revoked')
    if (agent.status === 'pending' && !allowPending) throw new HttpError(403, 'this agent is still waiting for approval')
    this.run('UPDATE agents SET last_seen_at = ? WHERE id = ?', now(), agent.id)
    return agent
  }

  private registerRoutes() {
    // public
    this.route('GET', '/api/config', this.getConfig)
    this.route('POST', '/api/bw/prelogin', this.bwPrelogin)
    this.route('POST', '/api/bw/token', this.bwToken)
    this.route('POST', '/api/bw/send-email-login', this.bwSendEmailLogin)
    this.route('GET', '/api/bw/sync', this.bwSync)
    this.route('POST', '/api/auth/passkey/options', this.passkeyLoginOptions)
    this.route('POST', '/api/auth/passkey/login', this.passkeyLogin)
    this.route('POST', '/api/auth/passkey/register-options', this.passkeyRegisterOptions)
    this.route('POST', '/api/auth/passkey/register', this.passkeyRegister)
    this.route('POST', '/api/auth/logout', this.logout)
    // app (session)
    this.route('GET', '/api/app/state', this.appState)
    this.route('POST', '/api/app/agents/:id/approve', this.approveAgent)
    this.route('POST', '/api/app/agents/:id/deny', this.denyAgent)
    this.route('DELETE', '/api/app/agents/:id', this.revokeAgent)
    this.route('POST', '/api/app/requests/:id/approve', this.approveRequest)
    this.route('POST', '/api/app/requests/:id/deny', this.denyRequest)
    this.route('DELETE', '/api/app/grants/:id', this.revokeGrant)
    this.route('POST', '/api/app/push/subscribe', this.pushSubscribe)
    this.route('POST', '/api/app/push/test', this.pushTest)
    // agents (bearer)
    this.route('POST', '/api/agent/register', this.agentRegister)
    this.route('GET', '/api/agent/status', this.agentStatus)
    this.route('POST', '/api/agent/requests', this.agentRequest)
    this.route('GET', '/api/agent/requests/:id', this.agentRequestStatus)
  }

  // ------------------------------------------------------------ public/auth

  private async getConfig(): Promise<Response> {
    const vapid = await this.vapid()
    const passkeys = this.row('SELECT COUNT(*) AS n FROM passkeys')!.n as number
    return json({ vapidPublicKey: vapid.publicKey, hasPasskeys: passkeys > 0, bwServer: this.env.BW_SERVER || 'https://vault.bitwarden.com' })
  }

  private async bwPrelogin(c: Ctx): Promise<Response> {
    const body = await this.body<{ email?: string }>(c.req)
    if (String(body.email || '').trim().toLowerCase() !== this.ownerEmail()) throw new HttpError(403, 'this broker belongs to another account')
    return bwProxy(this.env, 'prelogin', { email: this.ownerEmail() })
  }

  private async bwSendEmailLogin(c: Ctx): Promise<Response> {
    const body = await this.body<Record<string, unknown>>(c.req)
    if (String(body.email || '').trim().toLowerCase() !== this.ownerEmail()) throw new HttpError(403, 'this broker belongs to another account')
    return bwProxy(this.env, 'send-email-login', body)
  }

  private async bwToken(c: Ctx): Promise<Response> {
    const body = await this.body<{ fields?: Record<string, string> }>(c.req)
    const fields = body.fields || {}
    if (fields.grant_type === 'password') {
      this.checkOrigin(c)
      if (String(fields.username || '').trim().toLowerCase() !== this.ownerEmail()) throw new HttpError(403, 'this broker belongs to another account')
      const res = await bwProxy(this.env, 'token', fields)
      if (res.status !== 200) return res
      // Bitwarden just verified the master password (and 2FA) for the owner:
      // that is our proof of identity, so the response also opens a session.
      const headers = new Headers(res.headers)
      headers.append('set-cookie', await this.newSession('password'))
      this.log('login', { detail: 'master password' })
      return new Response(res.body, { status: res.status, headers })
    }
    if (fields.grant_type === 'refresh_token') {
      await this.session(c)
      return bwProxy(this.env, 'token', fields)
    }
    throw new HttpError(400, 'unsupported grant_type')
  }

  private async bwSync(c: Ctx): Promise<Response> {
    await this.session(c)
    const auth = c.req.headers.get('authorization')
    if (!auth) throw new HttpError(400, 'missing Bitwarden access token')
    return bwProxy(this.env, 'sync', null, auth)
  }

  private async newChallenge(purpose: string): Promise<string> {
    const challenge = randomToken()
    this.run('INSERT INTO challenges (challenge, purpose, expires_at) VALUES (?, ?, ?)', challenge, purpose, now() + CHALLENGE_TTL)
    return challenge
  }

  private consumeChallenge(clientDataJSON: string, purpose: string): string {
    const cd = parseClientData(fromB64(clientDataJSON))
    const found = this.row('SELECT challenge FROM challenges WHERE challenge = ? AND purpose = ? AND expires_at >= ?', cd.challenge, purpose, now())
    if (!found) throw new HttpError(400, 'unknown or expired challenge')
    this.run('DELETE FROM challenges WHERE challenge = ?', cd.challenge)
    return cd.challenge
  }

  private async passkeyLoginOptions(): Promise<Response> {
    const ids = this.rows('SELECT id FROM passkeys').map((r) => r.id as string)
    return json({ challenge: await this.newChallenge('login'), allowCredentials: ids })
  }

  private async passkeyLogin(c: Ctx): Promise<Response> {
    this.checkOrigin(c)
    const body = await this.body<{ id: string; authenticatorData: string; clientDataJSON: string; signature: string }>(c.req)
    const passkey = this.row('SELECT * FROM passkeys WHERE id = ?', String(body.id || ''))
    if (!passkey) throw new HttpError(401, 'unknown passkey')
    const challenge = this.consumeChallenge(String(body.clientDataJSON || ''), 'login')
    const counter = await verifyAssertion(
      body,
      { publicKey: passkey.public_key as string, alg: passkey.alg as number, signCount: passkey.sign_count as number },
      { challenge, origin: c.url.origin, rpId: c.url.hostname },
    )
    this.run('UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?', counter, now(), passkey.id)
    this.log('login', { detail: `passkey "${passkey.name}"` })
    return json({ ok: true }, 200, { 'set-cookie': await this.newSession('passkey') })
  }

  private async passkeyRegisterOptions(c: Ctx): Promise<Response> {
    await this.session(c)
    return json({
      challenge: await this.newChallenge('register'),
      rp: { id: c.url.hostname, name: 'WardenBroker' },
      user: { id: (await sha256Hex(this.ownerEmail())).slice(0, 32), name: this.ownerEmail(), displayName: this.ownerEmail() },
      excludeCredentials: this.rows('SELECT id FROM passkeys').map((r) => r.id as string),
      algorithms: SUPPORTED_ALGS,
    })
  }

  private async passkeyRegister(c: Ctx): Promise<Response> {
    await this.session(c)
    const body = await this.body<{ id: string; clientDataJSON: string; publicKey: string; alg: number; name?: string }>(c.req)
    const challenge = this.consumeChallenge(String(body.clientDataJSON || ''), 'register')
    checkClientData(parseClientData(fromB64(body.clientDataJSON)), 'webauthn.create', challenge, c.url.origin)
    if (!SUPPORTED_ALGS.includes(Number(body.alg))) throw new HttpError(400, 'unsupported passkey algorithm')
    if (!/^[A-Za-z0-9_-]{16,1024}$/.test(String(body.id || ''))) throw new HttpError(400, 'invalid credential id')
    if (!body.publicKey || fromB64(body.publicKey).length < 32) throw new HttpError(400, 'invalid public key')
    const name = String(body.name || 'Passkey').slice(0, 64)
    this.run(
      'INSERT OR REPLACE INTO passkeys (id, public_key, alg, sign_count, name, created_at) VALUES (?, ?, ?, 0, ?, ?)',
      body.id,
      body.publicKey,
      Number(body.alg),
      name,
      now(),
    )
    this.log('passkey.added', { detail: name })
    return json({ ok: true })
  }

  private async logout(c: Ctx): Promise<Response> {
    const token = (c.req.headers.get('cookie') || '').match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`))?.[1]
    if (token) this.run('DELETE FROM sessions WHERE token_hash = ?', await sha256Hex(token))
    return json({ ok: true }, 200, { 'set-cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0` })
  }

  // ------------------------------------------------------------------- app

  private async appState(c: Ctx): Promise<Response> {
    await this.session(c)
    const agents = this.rows('SELECT id, name, fingerprint, status, created_at, approved_at, last_seen_at FROM agents WHERE status != ? ORDER BY created_at DESC', 'revoked')
    const grants = this.rows('SELECT id, agent_id, host, item_name, created_at, expires_at, uses, last_used_at FROM grants ORDER BY host')
    const requests = this.rows(
      `SELECT r.id, r.agent_id, r.host, r.reason, r.created_at, r.expires_at, a.name AS agent_name, a.fingerprint, a.public_key
       FROM requests r JOIN agents a ON a.id = r.agent_id WHERE r.status = 'pending' ORDER BY r.created_at`,
    )
    const logs = this.rows('SELECT id, ts, event, agent_name, host, detail FROM logs ORDER BY id DESC LIMIT 200')
    const pushCount = this.row('SELECT COUNT(*) AS n FROM push_subscriptions')!.n as number
    const passkeys = this.rows('SELECT id, name, created_at, last_used_at FROM passkeys ORDER BY created_at')
    return json({
      pendingAgents: agents.filter((a) => a.status === 'pending'),
      pendingRequests: requests,
      agents: agents.filter((a) => a.status === 'active').map((a) => ({ ...a, grants: grants.filter((g) => g.agent_id === a.id) })),
      logs,
      pushSubscriptions: pushCount,
      passkeys,
    })
  }

  private async approveAgent(c: Ctx): Promise<Response> {
    await this.session(c)
    const agent = this.row("SELECT * FROM agents WHERE id = ? AND status = 'pending'", c.params[0])
    if (!agent) throw new HttpError(404, 'no such pending agent')
    this.run("UPDATE agents SET status = 'active', approved_at = ? WHERE id = ?", now(), agent.id)
    this.log('agent.approved', { agentId: agent.id as string, agentName: agent.name as string })
    this.wake(`agent:${agent.id}`)
    return json({ ok: true })
  }

  private async denyAgent(c: Ctx): Promise<Response> {
    await this.session(c)
    const agent = this.row("SELECT * FROM agents WHERE id = ? AND status = 'pending'", c.params[0])
    if (!agent) throw new HttpError(404, 'no such pending agent')
    this.run("UPDATE agents SET status = 'revoked' WHERE id = ?", agent.id)
    this.log('agent.denied', { agentId: agent.id as string, agentName: agent.name as string })
    this.wake(`agent:${agent.id}`)
    return json({ ok: true })
  }

  private async revokeAgent(c: Ctx): Promise<Response> {
    await this.session(c)
    const agent = this.row("SELECT * FROM agents WHERE id = ? AND status != 'revoked'", c.params[0])
    if (!agent) throw new HttpError(404, 'no such agent')
    this.run("UPDATE agents SET status = 'revoked' WHERE id = ?", agent.id)
    this.run('DELETE FROM grants WHERE agent_id = ?', agent.id)
    const pending = this.rows("SELECT id FROM requests WHERE agent_id = ? AND status = 'pending'", agent.id)
    this.run("UPDATE requests SET status = 'denied', resolved_at = ?, ciphertext = NULL WHERE agent_id = ? AND status IN ('pending', 'approved')", now(), agent.id)
    for (const r of pending) this.wake(`req:${r.id}`)
    this.log('agent.revoked', { agentId: agent.id as string, agentName: agent.name as string })
    this.wake(`agent:${agent.id}`)
    return json({ ok: true })
  }

  private async approveRequest(c: Ctx): Promise<Response> {
    await this.session(c)
    const body = await this.body<{ ciphertext?: string; itemName?: string; duration?: number }>(c.req)
    const request = this.row("SELECT r.*, a.name AS agent_name FROM requests r JOIN agents a ON a.id = r.agent_id WHERE r.id = ? AND r.status = 'pending'", c.params[0])
    if (!request) throw new HttpError(404, 'no such pending request')
    const ciphertext = String(body.ciphertext || '')
    if (!ciphertext || ciphertext.length > MAX_CIPHERTEXT || !/^[A-Za-z0-9_-]+$/.test(ciphertext)) throw new HttpError(400, 'invalid ciphertext')
    const itemName = String(body.itemName || '').slice(0, 200)
    // duration: seconds (at least a minute, so an agent can retry a failed step
    // without asking again), or -1 = until revoked
    const duration = Number(body.duration ?? 3600)
    if (!Number.isInteger(duration) || (duration !== -1 && (duration < 60 || duration > 365 * 24 * 3600))) {
      throw new HttpError(400, 'duration must be -1 (until revoked) or 60 seconds to a year')
    }
    const t = now()
    this.run("UPDATE requests SET status = 'approved', ciphertext = ?, item_name = ?, duration = ?, resolved_at = ? WHERE id = ?", ciphertext, itemName, duration, t, request.id)
    {
      this.run(
        `INSERT INTO grants (id, agent_id, host, ciphertext, item_name, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(agent_id, host) DO UPDATE SET id = excluded.id, ciphertext = excluded.ciphertext, item_name = excluded.item_name,
           created_at = excluded.created_at, expires_at = excluded.expires_at, uses = 0, last_used_at = NULL`,
        randomId(),
        request.agent_id,
        request.host,
        ciphertext,
        itemName,
        t,
        duration === -1 ? null : t + duration * 1000,
      )
    }
    this.log('secret.approved', {
      agentId: request.agent_id as string,
      agentName: request.agent_name as string,
      host: request.host as string,
      detail: `${itemName} · ${describeDuration(duration)}`,
    })
    this.wake(`req:${request.id}`)
    return json({ ok: true })
  }

  private async denyRequest(c: Ctx): Promise<Response> {
    await this.session(c)
    const request = this.row("SELECT r.*, a.name AS agent_name FROM requests r JOIN agents a ON a.id = r.agent_id WHERE r.id = ? AND r.status = 'pending'", c.params[0])
    if (!request) throw new HttpError(404, 'no such pending request')
    this.run("UPDATE requests SET status = 'denied', resolved_at = ? WHERE id = ?", now(), request.id)
    this.log('secret.denied', { agentId: request.agent_id as string, agentName: request.agent_name as string, host: request.host as string })
    this.wake(`req:${request.id}`)
    return json({ ok: true })
  }

  private async revokeGrant(c: Ctx): Promise<Response> {
    await this.session(c)
    const grant = this.row('SELECT g.*, a.name AS agent_name FROM grants g JOIN agents a ON a.id = g.agent_id WHERE g.id = ?', c.params[0])
    if (!grant) throw new HttpError(404, 'no such grant')
    this.run('DELETE FROM grants WHERE id = ?', grant.id)
    this.log('grant.revoked', { agentId: grant.agent_id as string, agentName: grant.agent_name as string, host: grant.host as string, detail: grant.item_name as string })
    return json({ ok: true })
  }

  private async pushSubscribe(c: Ctx): Promise<Response> {
    await this.session(c)
    const body = await this.body<{ endpoint?: string; keys?: { p256dh?: string; auth?: string } }>(c.req)
    const endpoint = String(body.endpoint || '')
    const scheme = this.env.DEV_ALLOW_INSECURE_PUSH === '1' ? /^https?:\/\// : /^https:\/\//
    if (!scheme.test(endpoint) || endpoint.length > 2048) throw new HttpError(400, 'invalid push endpoint')
    const p256dh = String(body.keys?.p256dh || '')
    const auth = String(body.keys?.auth || '')
    if (fromB64(p256dh).length !== 65 || fromB64(auth).length !== 16) throw new HttpError(400, 'invalid push keys')
    this.run(
      'INSERT INTO push_subscriptions (endpoint, p256dh, auth, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(endpoint) DO UPDATE SET p256dh = excluded.p256dh, auth = excluded.auth',
      endpoint,
      p256dh,
      auth,
      now(),
    )
    return json({ ok: true })
  }

  private async pushTest(c: Ctx): Promise<Response> {
    await this.session(c)
    const sent = await this.notify({ title: 'WardenBroker', body: 'Notifications are working.', tag: 'test' })
    return json({ sent })
  }

  private async vapid(): Promise<VapidKeys> {
    const stored = this.kvGet('vapid')
    if (stored) return JSON.parse(stored)
    const keys = await generateVapidKeys()
    this.kvSet('vapid', JSON.stringify(keys))
    return keys
  }

  private async notify(message: { title: string; body: string; tag: string }): Promise<number> {
    const subs = this.rows('SELECT endpoint, p256dh, auth FROM push_subscriptions') as unknown as PushSubscriptionRecord[]
    if (!subs.length) return 0
    const keys = await this.vapid()
    const subject = this.env.VAPID_SUBJECT || `mailto:${this.ownerEmail()}`
    let sent = 0
    await Promise.all(
      subs.map(async (sub) => {
        try {
          const status = await sendPush(sub, { ...message, url: '/' }, keys, subject)
          if (status === 404 || status === 410) this.run('DELETE FROM push_subscriptions WHERE endpoint = ?', sub.endpoint)
          else if (status < 300) sent++
          else console.warn('push failed', status)
        } catch (err) {
          console.warn('push failed', err)
        }
      }),
    )
    return sent
  }

  // ---------------------------------------------------------------- agents

  private async agentRegister(c: Ctx): Promise<Response> {
    const body = await this.body<{ name?: string; publicKey?: string }>(c.req)
    const name = String(body.name || '').trim()
    if (!name || name.length > 64 || /[\u0000-\u001f]/.test(name)) throw new HttpError(400, 'name must be 1-64 printable characters')
    const publicKey = String(body.publicKey || '')
    let raw: Uint8Array
    try {
      raw = fromB64(publicKey)
    } catch {
      throw new HttpError(400, 'invalid public key')
    }
    if (raw.length !== 65 || raw[0] !== 4) throw new HttpError(400, 'publicKey must be an uncompressed P-256 point')
    try {
      await crypto.subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
    } catch {
      throw new HttpError(400, 'publicKey is not a valid P-256 point')
    }
    const pending = this.row("SELECT COUNT(*) AS n FROM agents WHERE status = 'pending'")!.n as number
    if (pending >= MAX_PENDING_AGENTS) throw new HttpError(429, 'too many agents are already waiting for approval')
    // Registration is unauthenticated by design; cap it so a leaked broker URL can't be used to spam the owner's phone.
    const recent = this.row('SELECT COUNT(*) AS n FROM agents WHERE created_at > ?', now() - 3600 * 1000)!.n as number
    if (recent >= MAX_REGISTRATIONS_PER_HOUR) throw new HttpError(429, 'too many registrations in the last hour, try again later')
    const id = randomId()
    const token = randomToken()
    const fp = await fingerprint(publicKey)
    this.run(
      "INSERT INTO agents (id, name, public_key, fingerprint, token_hash, status, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
      id,
      name,
      publicKey,
      fp,
      await sha256Hex(token),
      now(),
    )
    this.log('agent.registered', { agentId: id, agentName: name, detail: fp })
    this.ctx.waitUntil(this.notify({ title: 'New agent', body: `“${name}” wants to connect (${fp})`, tag: `agent-${id}` }))
    return json({ id, token, fingerprint: fp, status: 'pending' }, 201)
  }

  private async agentStatus(c: Ctx): Promise<Response> {
    let agent = await this.agent(c, true)
    if (agent.status === 'pending') {
      await this.wait(`agent:${agent.id}`, Number(c.url.searchParams.get('wait') || 0))
      agent = this.row('SELECT * FROM agents WHERE id = ?', agent.id)!
    }
    if (agent.status === 'revoked') return json({ id: agent.id, status: 'denied' }, 403)
    return json({ id: agent.id, name: agent.name, fingerprint: agent.fingerprint, status: agent.status })
  }

  private async agentRequest(c: Ctx): Promise<Response> {
    const agent = await this.agent(c)
    const body = await this.body<{ kind?: string; host?: string; reason?: string }>(c.req)
    const host = requestTarget(body)
    const reason = String(body.reason || '').trim()
    if (!reason) throw new HttpError(400, 'a reason is required: tell the user why you need this secret')
    if (reason.length > 500) throw new HttpError(400, 'reason must be at most 500 characters')
    const grant = this.row('SELECT * FROM grants WHERE agent_id = ? AND host = ? AND (expires_at IS NULL OR expires_at >= ?)', agent.id, host, now())
    if (grant) {
      this.run('UPDATE grants SET uses = uses + 1, last_used_at = ? WHERE id = ?', now(), grant.id)
      this.log('secret.served', { agentId: agent.id as string, agentName: agent.name as string, host, detail: `${grant.item_name} · ${reason}` })
      return json({ status: 'approved', host, ciphertext: grant.ciphertext, itemName: grant.item_name, grantExpiresAt: grant.expires_at })
    }
    const existing = this.row("SELECT id FROM requests WHERE agent_id = ? AND host = ? AND status = 'pending'", agent.id, host)
    if (existing) return json({ id: existing.id, status: 'pending', host }, 202)
    const pending = this.row("SELECT COUNT(*) AS n FROM requests WHERE agent_id = ? AND status = 'pending'", agent.id)!.n as number
    if (pending >= MAX_PENDING_REQUESTS_PER_AGENT) throw new HttpError(429, 'too many pending requests for this agent')
    const id = randomId()
    const t = now()
    this.run("INSERT INTO requests (id, agent_id, host, reason, status, created_at, expires_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)", id, agent.id, host, reason, t, t + REQUEST_TTL)
    this.log('secret.requested', { agentId: agent.id as string, agentName: agent.name as string, host, detail: reason })
    this.ctx.waitUntil(this.notify({ title: `${agent.name} needs ${describeTarget(host)}`, body: reason, tag: `req-${id}` }))
    return json({ id, status: 'pending', host }, 202)
  }

  private async agentRequestStatus(c: Ctx): Promise<Response> {
    const agent = await this.agent(c)
    const find = () => this.row('SELECT * FROM requests WHERE id = ? AND agent_id = ?', c.params[0], agent.id)
    let request = find()
    if (!request) throw new HttpError(404, 'no such request')
    if (request.status === 'pending') {
      await this.wait(`req:${request.id}`, Number(c.url.searchParams.get('wait') || 0))
      this.sweep()
      request = find()!
    }
    if (request.status === 'approved') {
      if (!request.ciphertext) return json({ id: request.id, status: 'expired', host: request.host })
      // Hand the ciphertext over once; any grant keeps its own copy.
      this.run("UPDATE requests SET status = 'delivered', ciphertext = NULL WHERE id = ?", request.id)
      return json({ id: request.id, status: 'approved', host: request.host, ciphertext: request.ciphertext, itemName: request.item_name })
    }
    if (request.status === 'delivered') return json({ id: request.id, status: 'delivered', host: request.host }, 410)
    return json({ id: request.id, status: request.status, host: request.host })
  }
}

/**
 * What a request asks for: a host (kind "host", the default), or a payment card
 * (kind "card"). Cards are never matched by host, so a card request must not
 * name one; the user always picks the card on their phone.
 */
function requestTarget(body: { kind?: string; host?: string }): string {
  const kind = body.kind ?? 'host'
  if (kind === 'card') {
    if (body.host) throw new HttpError(400, 'card requests take no host: the user picks the card on their phone')
    return CARD_TARGET
  }
  if (kind !== 'host') throw new HttpError(400, 'kind must be "host" or "card"')
  const host = normalizeHost(String(body.host || ''))
  if (!host) throw new HttpError(400, 'host is required')
  return host
}

function describeDuration(seconds: number): string {
  if (seconds === -1) return 'until revoked'
  if (seconds % 86400 === 0) return `${seconds / 86400}d`
  if (seconds % 3600 === 0) return `${seconds / 3600}h`
  return `${Math.round(seconds / 60)}m`
}

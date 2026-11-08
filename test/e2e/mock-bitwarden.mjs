// A tiny Bitwarden-compatible server for end-to-end tests.
//
// It builds a vault with the real Bitwarden key hierarchy (PBKDF2 master key,
// HKDF-stretched key, protected user key, per-item keys, an organisation key
// wrapped with RSA-OAEP) so the PWA's crypto is exercised for real. It also
// doubles as a Web Push service: subscriptions pointing at /push/<id> are
// recorded so tests can decrypt what the broker sent.
import http from 'node:http'
import { createHmac } from 'node:crypto'

const subtle = globalThis.crypto.subtle
const te = new TextEncoder()
const b64 = (u8) => Buffer.from(u8).toString('base64')
const concat = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p)))

async function pbkdf2(pw, salt, iterations) {
  const key = await subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveBits'])
  return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256))
}
async function hmac(key, data) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return new Uint8Array(await subtle.sign('HMAC', k, data))
}
async function expand(prk, info) {
  return (await hmac(prk, concat(te.encode(info), [1]))).slice(0, 32)
}
async function encrypt(plain, key) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(16))
  const k = await subtle.importKey('raw', key.enc, 'AES-CBC', false, ['encrypt'])
  const data = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, k, typeof plain === 'string' ? te.encode(plain) : plain))
  const mac = await hmac(key.mac, concat(iv, data))
  return `2.${b64(iv)}|${b64(data)}|${b64(mac)}`
}
const split = (bytes) => ({ enc: bytes.slice(0, 32), mac: bytes.slice(32, 64) })
const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n))

export function totp(secretB32, t = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const c of secretB32.replace(/=+$/, '').toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, '0')
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)))
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(Math.floor(t / 1000 / 30)))
  const h = createHmac('sha1', key).update(msg).digest()
  const off = h[h.length - 1] & 15
  return String((h.readUInt32BE(off) & 0x7fffffff) % 1e6).padStart(6, '0')
}

export const ACCOUNT = {
  email: 'owner@example.com',
  password: 'correct horse battery staple',
  iterations: 100000,
  twoFactorSecret: 'JBSWY3DPEHPK3PXP',
}

export const ITEM_TOTP_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'

export const CARDS = {
  personal: { name: 'Personal Visa', cardholderName: 'Ada Lovelace', brand: 'Visa', number: '4111111111111111', expMonth: '4', expYear: '2029', code: '737' },
  claw: { name: 'Claw Credit Card', cardholderName: 'Claw Bot', brand: 'Mastercard', number: '5555555555554444', expMonth: '12', expYear: '2030', code: '321' },
}

export async function startMockBitwarden(port) {
  const masterKey = await pbkdf2(te.encode(ACCOUNT.password), te.encode(ACCOUNT.email), ACCOUNT.iterations)
  const hash = b64(await pbkdf2(masterKey, te.encode(ACCOUNT.password), 1))
  const stretched = { enc: await expand(masterKey, 'enc'), mac: await expand(masterKey, 'mac') }
  const userKeyBytes = rand(64)
  const userKey = split(userKeyBytes)

  const rsa = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['encrypt', 'decrypt'])
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', rsa.privateKey))
  const orgKeyBytes = rand(64)
  const orgKey = split(orgKeyBytes)
  const orgKeyEnc = `4.${b64(new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, rsa.publicKey, orgKeyBytes)))}`
  const itemKeyBytes = rand(64)
  const itemKey = split(itemKeyBytes)

  const login = async (key, { name, username = '', password = '', totp = '', uris = [], notes = '', fields = [] }, extra = {}) => ({
    Id: globalThis.crypto.randomUUID(),
    Type: 1,
    Name: await encrypt(name, key),
    Notes: notes ? await encrypt(notes, key) : null,
    Login: {
      Username: username ? await encrypt(username, key) : null,
      Password: password ? await encrypt(password, key) : null,
      Totp: totp ? await encrypt(totp, key) : null,
      Uris: await Promise.all(uris.map(async (u) => ({ Uri: await encrypt(u, key), Match: null }))),
    },
    Fields: await Promise.all(fields.map(async (f) => ({ Name: await encrypt(f.name, key), Value: await encrypt(f.value, key), Type: 1 }))),
    OrganizationId: null,
    DeletedDate: null,
    Key: null,
    ...extra,
  })

  // Card items (type 3) keep their data in Card, not Login, and have no URIs.
  const card = async (key, { name, ...fields }) => ({
    Id: globalThis.crypto.randomUUID(),
    Type: 3,
    Name: await encrypt(name, key),
    Notes: null,
    Login: null,
    Card: Object.fromEntries(
      await Promise.all(Object.entries(fields).map(async ([k, v]) => [k.charAt(0).toUpperCase() + k.slice(1), v ? await encrypt(v, key) : null])),
    ),
    Fields: [],
    OrganizationId: null,
    DeletedDate: null,
    Key: null,
  })

  const ciphers = [
    await login(userKey, { name: 'GitHub', username: 'octocat', password: 'gh-pass-123', totp: ITEM_TOTP_SECRET, uris: ['https://github.com/login'] }),
    await login(itemKey, { name: 'GitLab work', username: 'me', password: 'gl-pass-456', uris: ['gitlab.com'] }, { Key: await encrypt(itemKeyBytes, userKey) }),
    await login(userKey, { name: 'Example A', password: 'example-a', uris: ['https://example.com'] }),
    await login(userKey, { name: 'Example C admin', password: 'example-c', uris: ['https://example.com/admin'] }),
    await login(userKey, { name: 'Example login', password: 'example-login', uris: ['https://login.example.com'] }),
    await login(userKey, { name: 'OpenAI', uris: ['https://api.openai.com'], fields: [{ name: 'API Key', value: 'sk-test-789' }], notes: 'project: e2e' }),
    await login(userKey, { name: 'Deleted thing', password: 'nope', uris: ['https://deleted.example'] }, { DeletedDate: new Date().toISOString() }),
    await login(orgKey, { name: 'Org DB', username: 'dbadmin', password: 'org-db-pass', uris: ['db.internal.example'] }, { OrganizationId: 'org-1' }),
    await card(userKey, CARDS.personal),
    await card(userKey, CARDS.claw),
  ]

  const sync = {
    Profile: {
      Email: ACCOUNT.email,
      Key: await encrypt(userKeyBytes, stretched),
      PrivateKey: await encrypt(pkcs8, userKey),
      Organizations: [{ Id: 'org-1', Name: 'Acme', Key: orgKeyEnc }],
    },
    Ciphers: ciphers,
  }

  const state = {
    accessTokens: new Set(),
    refreshTokens: new Set(),
    rememberTokens: new Set(),
    pushes: [],
    requests: [],
    onPush: null,
  }

  const send = (res, status, body) => {
    res.writeHead(status, { 'content-type': 'application/json' })
    res.end(JSON.stringify(body))
  }
  const issue = () => {
    const access = `at-${b64(rand(12))}`
    const refresh = `rt-${b64(rand(12))}`
    state.accessTokens.add(access)
    state.refreshTokens.add(refresh)
    return { access_token: access, refresh_token: refresh, expires_in: 3600, token_type: 'Bearer', Key: sync.Profile.Key, PrivateKey: sync.Profile.PrivateKey }
  }

  const server = http.createServer(async (req, res) => {
    const chunks = []
    for await (const c of req) chunks.push(c)
    const raw = Buffer.concat(chunks)
    const url = new URL(req.url, `http://${req.headers.host}`)
    state.requests.push({ method: req.method, path: url.pathname, headers: req.headers })
    if (req.method === 'POST' && url.pathname === '/identity/accounts/prelogin') {
      return send(res, 200, { Kdf: 0, KdfIterations: ACCOUNT.iterations, KdfMemory: null, KdfParallelism: null })
    }
    if (req.method === 'POST' && url.pathname === '/identity/connect/token') {
      const f = Object.fromEntries(new URLSearchParams(raw.toString()))
      if (f.grant_type === 'refresh_token') {
        if (!state.refreshTokens.has(f.refresh_token)) return send(res, 400, { error: 'invalid_grant' })
        state.refreshTokens.delete(f.refresh_token) // rotate, like one-time-use refresh tokens
        return send(res, 200, issue())
      }
      if (f.grant_type !== 'password') return send(res, 400, { error: 'unsupported_grant_type' })
      if (f.username !== ACCOUNT.email || f.password !== hash) {
        return send(res, 400, { error: 'invalid_grant', error_description: 'invalid_username_or_password', ErrorModel: { Message: 'Username or password is incorrect. Try again.' } })
      }
      if (req.headers['auth-email'] !== Buffer.from(ACCOUNT.email).toString('base64url')) return send(res, 400, { error: 'missing auth-email header' })
      const remembered = f.twoFactorProvider === '5' && state.rememberTokens.has(f.twoFactorToken)
      const validCode = f.twoFactorProvider === '0' && f.twoFactorToken === totp(ACCOUNT.twoFactorSecret)
      if (!remembered && !validCode) {
        if (f.twoFactorToken && f.twoFactorProvider === '0') return send(res, 400, { error: 'invalid_grant', error_description: 'Two-step token is invalid. Try again.' })
        return send(res, 400, { error: 'invalid_grant', error_description: 'Two factor required.', TwoFactorProviders: ['0', '1'], TwoFactorProviders2: { 0: null, 1: { Email: 'o***@example.com' } } })
      }
      const out = issue()
      if (validCode && f.twoFactorRemember === '1') {
        const remember = `rem-${b64(rand(12))}`
        state.rememberTokens.add(remember)
        out.TwoFactorToken = remember
      }
      return send(res, 200, out)
    }
    if (req.method === 'GET' && url.pathname === '/api/sync') {
      const token = (req.headers.authorization || '').replace(/^Bearer /, '')
      if (!state.accessTokens.has(token)) return send(res, 401, { message: 'unauthorized' })
      return send(res, 200, sync)
    }
    if (req.method === 'POST' && url.pathname === '/api/two-factor/send-email-login') return send(res, 200, {})
    if (req.method === 'POST' && url.pathname.startsWith('/push/')) {
      const push = { id: url.pathname.slice(6), headers: req.headers, body: raw }
      state.pushes.push(push)
      state.onPush?.(push)
      res.writeHead(201)
      return res.end()
    }
    send(res, 404, { message: 'not found' })
  })
  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve))
  return { server, state, close: () => new Promise((r) => server.close(r)) }
}

// End-to-end test: real Worker (wrangler dev / workerd), real PWA in Chromium
// with a virtual passkey authenticator (PRF enabled), real Go CLI, and a mock
// Bitwarden server that uses genuine Bitwarden crypto.
//
//   npm run test:e2e            (builds the PWA and the CLI first)
//   E2E_SKIP_BUILD=1 npm run test:e2e
//   E2E_HEADED=1 npm run test:e2e
import { spawn, execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import assert from 'node:assert/strict'
import { ACCOUNT, ITEM_TOTP_SECRET, startMockBitwarden, totp } from './mock-bitwarden.mjs'
import { decryptPush, fakeSubscription } from './push.mjs'

const require = createRequire(import.meta.url)
let playwright
try {
  playwright = require('playwright')
} catch {
  playwright = require('/opt/node-tools/node_modules/playwright')
}

const ROOT = new URL('../../', import.meta.url).pathname
const TMP = mkdtempSync(join(tmpdir(), 'wardenbroker-e2e-'))
const BW_PORT = 18790 + Math.floor(Math.random() * 500)
const WB_PORT = 19790 + Math.floor(Math.random() * 500)
const ORIGIN = `http://localhost:${WB_PORT}`
const API = `http://127.0.0.1:${WB_PORT}`
const CLI = join(TMP, 'wardenbroker')
const children = []
const SHOTS = process.env.E2E_SCREENSHOTS // directory to save UI screenshots into
let shotN = 0
async function shot(name) {
  if (SHOTS) await sleep(350)
  if (SHOTS) await ctx.page.screenshot({ path: join(SHOTS, `${String(++shotN).padStart(2, '0')}-${name}.png`), fullPage: true })
}
const env = {
  ...process.env,
  NO_PROXY: ['127.0.0.1', 'localhost', process.env.NO_PROXY].filter(Boolean).join(','),
  no_proxy: ['127.0.0.1', 'localhost', process.env.no_proxy].filter(Boolean).join(','),
}

// ------------------------------------------------------------------ harness

let passed = 0
async function step(name, fn) {
  const started = Date.now()
  try {
    await fn()
    passed++
    console.log(`  ✓ ${name} (${Date.now() - started}ms)`)
  } catch (err) {
    console.log(`  ✗ ${name}`)
    try {
      console.log('    page text:', JSON.stringify((await ctx?.page?.innerText('body'))?.slice(0, 1500)))
    } catch {}
    throw err
  }
}

function cli(args, { config = join(TMP, 'agent.json') } = {}) {
  const proc = spawn(CLI, args, { env: { ...env, WARDENBROKER_CONFIG: config }, stdio: ['ignore', 'pipe', 'pipe'] })
  const out = { stdout: '', stderr: '' }
  proc.stdout.on('data', (d) => (out.stdout += d))
  proc.stderr.on('data', (d) => (out.stderr += d))
  out.done = new Promise((resolve) => proc.on('close', (code) => resolve(code)))
  out.proc = proc
  out.waitFor = async (re, ms = 15000) => {
    const end = Date.now() + ms
    while (Date.now() < end) {
      const m = (out.stdout + out.stderr).match(re)
      if (m) return m
      await sleep(50)
    }
    throw new Error(`CLI output never matched ${re}:\n${out.stdout}\n${out.stderr}`)
  }
  children.push(proc)
  return out
}

async function finished(run, ms = 20000) {
  const code = await Promise.race([run.done, sleep(ms).then(() => 'timeout')])
  if (code === 'timeout') throw new Error(`CLI did not finish:\n${run.stdout}\n${run.stderr}`)
  return code
}

async function api(path, { method = 'GET', body, headers = {} } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  })
  let data = null
  try {
    data = await res.json()
  } catch {}
  return { status: res.status, data }
}

// -------------------------------------------------------------------- setup

async function setup() {
  if (!process.env.E2E_SKIP_BUILD) {
    console.log('building PWA…')
    execFileSync('npx', ['vite', 'build', '--logLevel', 'warn'], { cwd: ROOT, stdio: 'inherit', env })
  }
  console.log('building CLI…')
  execFileSync('go', ['build', '-o', CLI, './cmd/wardenbroker'], { cwd: join(ROOT, 'cli'), stdio: 'inherit', env })

  const bw = await startMockBitwarden(BW_PORT)
  console.log(`mock Bitwarden on :${BW_PORT}`)

  const wrangler = spawn(
    join(ROOT, 'node_modules/.bin/wrangler'),
    [
      'dev',
      '--port', String(WB_PORT),
      '--ip', '127.0.0.1',
      '--persist-to', join(TMP, 'state'),
      '--var', `OWNER_EMAIL:${ACCOUNT.email}`,
      '--var', `BW_SERVER:http://127.0.0.1:${BW_PORT}`,
      '--var', 'DEV_ALLOW_INSECURE_PUSH:1',
      '--show-interactive-dev-session=false',
    ],
    { cwd: ROOT, env: { ...env, WRANGLER_SEND_METRICS: 'false', CI: '1' }, stdio: ['ignore', 'pipe', 'pipe'] },
  )
  children.push(wrangler)
  let wlog = ''
  wrangler.stdout.on('data', (d) => (wlog += d))
  wrangler.stderr.on('data', (d) => (wlog += d))
  const end = Date.now() + 60000
  for (;;) {
    try {
      if ((await fetch(`${API}/api/config`)).ok) break
    } catch {}
    if (Date.now() > end) throw new Error(`wrangler dev did not start:\n${wlog}`)
    await sleep(300)
  }
  console.log(`wrangler dev on :${WB_PORT}`)

  const browser = await playwright.chromium.launch({ headless: !process.env.E2E_HEADED })
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true, deviceScaleFactor: SHOTS ? 2 : 1 })
  const page = await context.newPage()
  page.on('pageerror', (err) => console.log('    [page error]', err.message))
  const cdp = await context.newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf: true,
    },
  })
  return { bw, browser, page, cdp, authenticatorId, wlog: () => wlog }
}

// -------------------------------------------------------------------- tests

let ctx
async function main() {
  const t = await setup()
  ctx = t
  const { page, bw } = t
  const button = (name) => page.getByRole('button', { name, exact: true })
  const reload = () => page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))

  console.log('\nOnboarding')
  await step('the PWA asks for the Bitwarden login', async () => {
    await page.goto(ORIGIN)
    await page.getByRole('heading', { name: 'Sign in with Bitwarden' }).waitFor()
    await shot('login')
  })

  await step('a wrong master password is rejected by Bitwarden', async () => {
    await page.getByLabel('Email').fill(ACCOUNT.email)
    await page.getByLabel('Master password').fill('wrong password')
    await button('Sign in').click()
    await page.getByRole('alert').filter({ hasText: /incorrect/i }).waitFor()
  })

  await step('master password + authenticator 2FA signs in and decrypts the vault', async () => {
    await page.getByLabel('Master password').fill(ACCOUNT.password)
    await button('Sign in').click()
    await page.getByRole('heading', { name: 'Two-step login' }).waitFor()
    await shot('two-factor')
    await page.getByPlaceholder('123456').fill(totp(ACCOUNT.twoFactorSecret))
    await button('Continue').click()
    await page.getByRole('heading', { name: 'Unlock with a passkey' }).waitFor()
    await shot('passkey-setup')
    const token = bw.state.requests.find((r) => r.path === '/identity/connect/token')
    assert.equal(token.headers['bitwarden-client-name'], 'web')
  })

  await step('creating a passkey stores the vault key under its PRF output', async () => {
    await button('Create passkey').click()
    await page.getByRole('heading', { name: 'Turn on notifications' }).waitFor()
    const lock = await page.evaluate(() => JSON.parse(localStorage.getItem('wb.lock')))
    assert.equal(lock.email, ACCOUNT.email)
    assert.ok(lock.ct.length > 100, 'encrypted lock blob present')
    const raw = await page.evaluate(() => JSON.stringify(localStorage))
    assert.ok(!raw.includes(ACCOUNT.password), 'master password is never stored')
    await button('Not now').click()
    await page.getByText('No agents yet').waitFor()
    await shot('home-empty')
  })

  const sub = await fakeSubscription(`http://127.0.0.1:${BW_PORT}/push/phone`)
  await step('a push subscription can be registered', async () => {
    const res = await page.evaluate(async (body) => {
      const r = await fetch('/api/app/push/subscribe', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      return r.status
    }, sub.json)
    assert.equal(res, 200)
  })

  console.log('\nAgent registration')
  let fingerprint
  await step('registering an agent sends an encrypted push and shows an approval card', async () => {
    const pushed = new Promise((resolve) => (bw.state.onPush = resolve))
    const reg = cli(['register', '--url', ORIGIN, '--name', 'e2e-agent'])
    fingerprint = (await reg.waitFor(/Fingerprint: ([0-9A-F-]{19})/))[1]
    const push = await Promise.race([pushed, sleep(10000).then(() => null)])
    assert.ok(push, 'push delivered')
    assert.match(push.headers.authorization, /^vapid t=.+, k=.+/)
    assert.equal(push.headers['content-encoding'], 'aes128gcm')
    const message = JSON.parse(await decryptPush(push.body, sub))
    assert.equal(message.title, 'New agent')
    assert.ok(message.body.includes(fingerprint), 'push shows the fingerprint')
    await reload()
    await page.getByRole('heading', { name: 'e2e-agent' }).waitFor()
    await page.getByText(fingerprint).first().waitFor()
    await shot('agent-approval')
    await button('Connect').click()
    assert.equal(await finished(reg), 0, reg.stderr)
    assert.match(reg.stderr, /Approved/)
  })

  await step('an unapproved agent cannot request secrets', async () => {
    const reg = cli(['register', '--url', ORIGIN, '--name', 'intruder'], { config: join(TMP, 'intruder.json') })
    await reg.waitFor(/Waiting for approval/)
    const cfg = JSON.parse(execFileSync('cat', [join(TMP, 'intruder.json')]).toString())
    const res = await api('/api/agent/requests', { method: 'POST', headers: { authorization: `Bearer ${cfg.token}` }, body: { host: 'github.com', reason: 'x' } })
    assert.equal(res.status, 403)
    await reload()
    await page.getByRole('heading', { name: 'intruder' }).waitFor()
    await button('Deny').click()
    assert.equal(await finished(reg), 3)
    await page.getByText('Agents', { exact: true }).waitFor()
  })

  console.log('\nSecret exchange')
  const approve = async (host, { duration = 'Once', pick } = {}) => {
    await reload()
    await page.locator('h2.host', { hasText: host }).waitFor()
    if (pick) await page.getByRole('button', { name: new RegExp(`^${pick}`) }).click()
    await page.getByRole('radio', { name: duration }).click()
    await button('Approve').click()
    await page.locator('h2.host').waitFor({ state: 'detached' })
  }

  await step('a request is auto-matched to the vault item, approved once, decrypted by the CLI', async () => {
    const get = cli(['get', 'github.com', '--reason', 'push the release branch'])
    await get.waitFor(/Waiting for approval/)
    await reload()
    await page.getByText('push the release branch').waitFor()
    await page.getByRole('button', { name: /^GitHub/ }).waitFor()
    await page.getByText(/Shares username, password, TOTP seed/).waitFor()
    await shot('secret-request')
    await approve('github.com')
    assert.equal(await finished(get), 0, get.stderr)
    assert.equal(get.stdout.trim(), 'gh-pass-123')
  })

  await step('"once" leaves no standing access: the next request asks again', async () => {
    const get = cli(['get', 'https://github.com/settings', '--field', 'totp', '--reason', 'log in'])
    await get.waitFor(/Waiting for approval/)
    await approve('github.com', { duration: '1 hour' })
    assert.equal(await finished(get), 0, get.stderr)
    const code = get.stdout.trim()
    assert.match(code, /^\d{6}$/)
    const window = [Date.now() - 30000, Date.now(), Date.now() + 30000].map((ts) => {
      const secret = ITEM_TOTP_SECRET
      return totp(secret, ts)
    })
    assert.ok(window.includes(code), `TOTP ${code} should be current`)
  })

  await step('a timed grant is served immediately without asking the user', async () => {
    const started = Date.now()
    const get = cli(['get', 'github.com', '--field', 'username', '--reason', 'whoami'])
    assert.equal(await finished(get, 5000), 0, get.stderr)
    assert.equal(get.stdout.trim(), 'octocat')
    assert.ok(Date.now() - started < 3000, 'no approval round-trip')
    assert.ok(!get.stderr.includes('Waiting'), 'did not wait')
  })

  await step('ambiguous hosts make the user pick; per-item keys decrypt', async () => {
    const get = cli(['get', 'example.com', '--reason', 'admin task'])
    await get.waitFor(/Waiting for approval/)
    await reload()
    await page.getByText(/items match/).waitFor()
    await shot('secret-request-pick')
    await approve('example.com', { pick: 'Example C admin' })
    assert.equal(await finished(get), 0, get.stderr)
    assert.equal(get.stdout.trim(), 'example-c')
  })

  await step('custom fields: an API key without a password', async () => {
    const get = cli(['get', 'api.openai.com', '--json', '--reason', 'run evals'])
    await get.waitFor(/Waiting for approval/)
    await approve('api.openai.com')
    assert.equal(await finished(get), 0, get.stderr)
    const item = JSON.parse(get.stdout)
    assert.equal(item.name, 'OpenAI')
    assert.deepEqual(item.fields, [{ name: 'API Key', value: 'sk-test-789' }])
  })

  await step('organization items decrypt through the RSA-wrapped org key', async () => {
    const get = cli(['get', 'db.internal.example', '--reason', 'run migrations'])
    await get.waitFor(/Waiting for approval/)
    await approve('db.internal.example')
    assert.equal(await finished(get), 0, get.stderr)
    assert.equal(get.stdout.trim(), 'org-db-pass')
  })

  await step('`run` injects secrets into a child process environment', async () => {
    const run = cli(['run', '--reason', 'deploy', '-e', 'GL=gitlab.com', '-e', 'GH_USER=github.com:username', '--', 'sh', '-c', 'echo "$GL/$GH_USER"; exit 7'])
    await run.waitFor(/Waiting for approval/)
    await approve('gitlab.com')
    assert.equal(await finished(run), 7, 'child exit code is propagated')
    assert.equal(run.stdout.trim(), 'gl-pass-456/octocat')
  })

  await step('a denied request makes the CLI exit with code 3', async () => {
    const get = cli(['get', 'nothing.example', '--reason', 'just curious'])
    await get.waitFor(/Waiting for approval/)
    await reload()
    await page.getByText(/No vault item matches nothing.example/).waitFor()
    await button('Deny').click()
    assert.equal(await finished(get), 3)
    assert.match(get.stderr, /denied/)
  })

  await step('revoking a grant from the agent list removes standing access', async () => {
    await page.getByRole('button', { name: /e2e-agent/ }).click()
    const grant = page.locator('.grants li', { hasText: 'github.com' })
    await grant.waitFor()
    await shot('agent-detail')
    await grant.getByRole('button', { name: 'Revoke' }).click()
    await grant.waitFor({ state: 'detached' })
    const get = cli(['get', 'github.com', '--reason', 'again'])
    await get.waitFor(/Waiting for approval/)
    await reload()
    await page.locator('h2.host', { hasText: 'github.com' }).waitFor()
    await button('Deny').click()
    assert.equal(await finished(get), 3)
  })

  await step('the activity log tells the story', async () => {
    await page.getByText('Shared github.com with e2e-agent').first().waitFor()
    await page.getByText('e2e-agent used its access to github.com').first().waitFor()
    await page.getByText('Denied nothing.example to e2e-agent').waitFor()
    await page.getByText("Revoked e2e-agent's access to github.com").waitFor()
  })

  console.log('\nLock and unlock')
  await step('locking forgets the vault; the passkey unlocks it again (cached vault + refresh)', async () => {
    await button('Lock').click()
    await page.getByRole('heading', { name: 'WardenBroker is locked' }).waitFor()
    await shot('locked')
    const state = await api('/api/app/state')
    assert.equal(state.status, 401)
    await button('Unlock with passkey').click()
    await page.getByText('Agents', { exact: true }).waitFor()
    await page.getByText(/7 vault items · synced/).waitFor()
  })

  await step('a fresh page load requires the passkey again', async () => {
    await page.reload()
    await page.getByRole('heading', { name: 'WardenBroker is locked' }).waitFor()
    await button('Unlock with passkey').click()
    await page.getByText('Agents', { exact: true }).waitFor()
  })

  await step('the rotated refresh token was re-sealed under the passkey (second unlock still syncs)', async () => {
    // The mock rotates refresh tokens (one-time use). The first unlock used and
    // replaced the stored one; this unlock can only sync if the new token was
    // written back into the passkey-encrypted blob.
    const refreshes = bw.state.requests.filter((r) => r.path === '/identity/connect/token').length
    assert.ok(refreshes >= 4, `expected logins + refreshes, saw ${refreshes}`)
    await page.getByText(/7 vault items · synced/).waitFor()
    assert.equal(await page.getByText(/Bitwarden session expired/).count(), 0)
  })

  await step('master password fallback: remembered 2FA, re-linking reuses the existing passkey', async () => {
    await button('Lock').click()
    await button('Use master password instead').click()
    assert.equal(await page.getByLabel('Email').inputValue(), ACCOUNT.email, 'email is remembered')
    await page.getByLabel('Master password').fill(ACCOUNT.password)
    await button('Sign in').click()
    await page.getByRole('heading', { name: 'Unlock with a passkey' }).waitFor()
    await button('Re-link passkey').click()
    await page.getByRole('heading', { name: 'Turn on notifications' }).waitFor()
    await button('Not now').click()
    await page.getByText('Agents', { exact: true }).waitFor()
    const { credentials } = await t.cdp.send('WebAuthn.getCredentials', { authenticatorId: t.authenticatorId })
    assert.equal(credentials.length, 1, 'no duplicate passkey was created')
    await page.reload()
    await button('Unlock with passkey').click()
    await page.getByText('Agents', { exact: true }).waitFor()
  })

  console.log('\nSecurity boundaries')
  await step('the app API requires a session', async () => {
    assert.equal((await api('/api/app/state')).status, 401)
    assert.equal((await api('/api/bw/sync', { headers: { authorization: 'Bearer x' } })).status, 401)
    assert.equal((await api('/api/auth/passkey/register-options', { method: 'POST', body: {} })).status, 401)
  })

  await step('cross-origin mutations are refused even with a session cookie', async () => {
    const cookies = await page.context().cookies()
    const session = cookies.find((c) => c.name === 'wb_session')
    assert.ok(session?.httpOnly && session.sameSite === 'Strict', 'session cookie is HttpOnly + SameSite=Strict')
    const res = await api('/api/app/push/test', { method: 'POST', body: {}, headers: { cookie: `wb_session=${session.value}`, origin: 'https://evil.example' } })
    assert.equal(res.status, 403)
  })

  await step('only the owner can use the Bitwarden login proxy', async () => {
    assert.equal((await api('/api/bw/prelogin', { method: 'POST', body: { email: 'someone@else.com' } })).status, 403)
    const token = await api('/api/bw/token', {
      method: 'POST',
      headers: { origin: API },
      body: { fields: { grant_type: 'password', username: 'someone@else.com', password: 'x' } },
    })
    assert.equal(token.status, 403)
    assert.equal((await api('/api/bw/token', { method: 'POST', body: { fields: { grant_type: 'refresh_token', refresh_token: 'x' } } })).status, 401)
  })

  await step('agent input is validated', async () => {
    assert.equal((await api('/api/agent/register', { method: 'POST', body: { name: 'x', publicKey: 'AAAA' } })).status, 400)
    assert.equal((await api('/api/agent/register', { method: 'POST', body: { name: '', publicKey: 'AAAA' } })).status, 400)
    assert.equal((await api('/api/agent/requests', { method: 'POST', headers: { authorization: 'Bearer nope' }, body: { host: 'a.com', reason: 'x' } })).status, 401)
    const cfg = JSON.parse(execFileSync('cat', [join(TMP, 'agent.json')]).toString())
    const noReason = await api('/api/agent/requests', { method: 'POST', headers: { authorization: `Bearer ${cfg.token}` }, body: { host: 'a.com' } })
    assert.equal(noReason.status, 400)
  })

  await step('the broker only ever stores ciphertext', async () => {
    const dump = execFileSync('sh', ['-c', `find ${join(TMP, 'state')} -type f -exec cat {} + | strings`], { maxBuffer: 64 << 20 }).toString()
    for (const secret of ['gh-pass-123', 'gl-pass-456', 'sk-test-789', 'org-db-pass', 'example-c', ACCOUNT.password]) {
      assert.ok(!dump.includes(secret), `${secret} must not appear in broker storage`)
    }
  })

  console.log('\nDisconnect')
  await step('disconnecting an agent locks it out', async () => {
    await reload()
    await page.getByRole('button', { name: /e2e-agent/ }).click().catch(() => {})
    page.once('dialog', (d) => d.accept())
    await button('Disconnect agent').click()
    await page.getByText('No agents yet').waitFor()
    const status = cli(['status'])
    assert.equal(await finished(status), 3)
    const get = cli(['get', 'github.com', '--reason', 'still there?'])
    assert.equal(await finished(get), 3)
  })

  console.log(`\n${passed} steps passed`)
  return t
}

const code = await main()
  .then(() => 0)
  .catch((err) => {
    console.error('\n', err)
    return 1
  })
try {
  await ctx?.browser?.close()
} catch {}
for (const c of children) {
  try {
    c.kill('SIGTERM')
  } catch {}
}
rmSync(TMP, { recursive: true, force: true })
process.exit(code)

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { load } from './bundle.mjs'

const bw = await load('web/src/bw.ts')
const item = (name, ...uris) => ({ id: name, name, uris: uris.map((u) => (typeof u === 'string' ? { uri: u, match: null } : u)), fields: [], username: '', password: '', totp: '', notes: '', organization: null, type: 1 })

test('baseDomain handles common second-level suffixes', () => {
  assert.equal(bw.baseDomain('api.github.com'), 'github.com')
  assert.equal(bw.baseDomain('github.com'), 'github.com')
  assert.equal(bw.baseDomain('www.bbc.co.uk'), 'bbc.co.uk')
  assert.equal(bw.baseDomain('a.b.example.com.au'), 'example.com.au')
  assert.equal(bw.baseDomain('10.0.0.1'), '10.0.0.1')
})

test('matchScore honours Bitwarden URI match types', () => {
  assert.equal(bw.matchScore(item('a', 'https://github.com/login'), 'github.com'), 2)
  assert.equal(bw.matchScore(item('a', 'github.com'), 'api.github.com'), 1)
  assert.equal(bw.matchScore(item('a', { uri: 'github.com', match: 1 }), 'api.github.com'), 0, 'host match is exact')
  assert.equal(bw.matchScore(item('a', { uri: 'https://github.com', match: 5 }), 'github.com'), 0, 'never')
  assert.equal(bw.matchScore(item('a', { uri: '^https://.*\\.corp\\.example/', match: 4 }), 'git.corp.example'), 2, 'regex')
  assert.equal(bw.matchScore(item('a', 'gitlab.com'), 'github.com'), 0)
})

test('candidatesFor auto-picks only an unambiguous best match', () => {
  const vault = [item('GitHub', 'https://github.com'), item('GitHub API', 'https://api.github.com'), item('Other', 'https://other.com')]
  assert.equal(bw.candidatesFor(vault, 'github.com').autoPick?.name, 'GitHub')
  assert.equal(bw.candidatesFor(vault, 'api.github.com').autoPick?.name, 'GitHub API')
  assert.equal(bw.candidatesFor(vault, 'gist.github.com').autoPick, null, 'two same-domain items tie')
  assert.equal(bw.candidatesFor(vault, 'gist.github.com').items.length, 2)
  assert.equal(bw.candidatesFor(vault, 'nope.dev').items.length, 0)
})

test('camelize normalises PascalCase server responses', () => {
  assert.deepEqual(bw.camelize({ Profile: { Key: 'k', Organizations: [{ Id: 1 }] } }), { profile: { key: 'k', organizations: [{ id: 1 }] } })
})

test('EncString round trip and MAC verification', async () => {
  const key = bw.symKey(crypto.getRandomValues(new Uint8Array(64)))
  const enc = await bw.encryptString('hunter2', key)
  assert.match(enc, /^2\./)
  assert.equal(await bw.decryptString(enc, key), 'hunter2')
  const [head, mac] = [enc.slice(0, enc.lastIndexOf('|')), enc.slice(enc.lastIndexOf('|') + 1)]
  const tampered = `${head}|${mac.startsWith('A') ? 'B' : 'A'}${mac.slice(1)}`
  await assert.rejects(bw.decryptString(tampered, key), /MAC/)
})

test('loginChallenge recognises 2FA and new-device prompts', () => {
  const twoFactor = new bw.BwError('Two factor required.', 400, { twoFactorProviders2: { 0: null, 1: {} } })
  assert.deepEqual(bw.loginChallenge(twoFactor), { kind: 'two-factor', providers: [0, 1] })
  const device = new bw.BwError('New device verification required', 400, {})
  assert.deepEqual(bw.loginChallenge(device), { kind: 'new-device' })
  assert.equal(bw.loginChallenge(new bw.BwError('nope', 400, {})), null)
})

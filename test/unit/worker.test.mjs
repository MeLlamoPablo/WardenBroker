import { test } from 'node:test'
import assert from 'node:assert/strict'
import { load } from './bundle.mjs'
import { decryptPush, fakeSubscription } from '../e2e/push.mjs'

const webauthn = await load('worker/webauthn.ts')
const webpush = await load('worker/webpush.ts')
const util = await load('worker/util.ts')
const te = new TextEncoder()
const b64url = (u8) => Buffer.from(u8).toString('base64url')

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data))
}

function rawToDer(raw) {
  const int = (b) => {
    let i = 0
    while (i < b.length - 1 && b[i] === 0) i++
    b = b.slice(i)
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b])
    return Buffer.concat([Buffer.from([2, b.length]), b])
  }
  const body = Buffer.concat([int(Buffer.from(raw.slice(0, 32))), int(Buffer.from(raw.slice(32)))])
  return Buffer.concat([Buffer.from([0x30, body.length]), body])
}

async function makeAssertion({ challenge, origin, rpId, flags = 0x05, counter = 0, keys, type = 'webauthn.get' }) {
  const clientDataJSON = te.encode(JSON.stringify({ type, challenge, origin }))
  const authData = new Uint8Array(37)
  authData.set(await sha256(te.encode(rpId)), 0)
  authData[32] = flags
  new DataView(authData.buffer).setUint32(33, counter)
  const signed = Buffer.concat([authData, await sha256(clientDataJSON)])
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, signed))
  return { authenticatorData: b64url(authData), clientDataJSON: b64url(clientDataJSON), signature: b64url(rawToDer(sig)) }
}

test('WebAuthn assertions are verified end to end', async () => {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const passkey = { publicKey: b64url(new Uint8Array(await crypto.subtle.exportKey('spki', keys.publicKey))), alg: -7, signCount: 0 }
  const expected = { challenge: 'abc', origin: 'https://wb.example', rpId: 'wb.example' }
  const ok = await makeAssertion({ ...expected, keys })
  assert.equal(await webauthn.verifyAssertion(ok, passkey, expected), 0)

  await assert.rejects(webauthn.verifyAssertion(await makeAssertion({ ...expected, keys, origin: 'https://evil.example' }), passkey, expected), /origin/)
  await assert.rejects(webauthn.verifyAssertion(await makeAssertion({ ...expected, keys, rpId: 'evil.example' }), passkey, expected), /RP ID/)
  await assert.rejects(webauthn.verifyAssertion(await makeAssertion({ ...expected, keys, flags: 0x01 }), passkey, expected), /verification/)
  await assert.rejects(webauthn.verifyAssertion(await makeAssertion({ ...expected, keys, challenge: 'zzz' }), passkey, expected), /challenge/)
  await assert.rejects(webauthn.verifyAssertion(await makeAssertion({ ...expected, keys, type: 'webauthn.create' }), passkey, expected), /type/)
  const other = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  await assert.rejects(webauthn.verifyAssertion(await makeAssertion({ ...expected, keys: other }), passkey, expected), /signature/)
  await assert.rejects(webauthn.verifyAssertion(await makeAssertion({ ...expected, keys, counter: 3 }), { ...passkey, signCount: 5 }, expected), /counter/)
})

test('derToRaw handles short and padded integers', () => {
  const raw = new Uint8Array(64)
  raw[31] = 1
  raw.fill(0xff, 32)
  assert.deepEqual(webauthn.derToRaw(rawToDer(raw)), raw)
})

test('Web Push payloads decrypt per RFC 8291', async () => {
  const sub = await fakeSubscription('https://push.example/x')
  const body = await webpush.encryptPayload(te.encode('{"title":"hi"}'), { endpoint: sub.json.endpoint, ...sub.json.keys })
  assert.equal(await decryptPush(body, sub), '{"title":"hi"}')
})

test('VAPID header is a valid ES256 JWT for the push origin', async () => {
  const keys = await webpush.generateVapidKeys()
  const header = await webpush.vapidHeader('https://fcm.googleapis.com/fcm/send/abc', keys, 'mailto:a@b.c')
  const [, jwt, k] = header.match(/^vapid t=([^,]+), k=(.+)$/)
  assert.equal(k, keys.publicKey)
  const [h, p, s] = jwt.split('.')
  assert.equal(JSON.parse(Buffer.from(p, 'base64url')).aud, 'https://fcm.googleapis.com')
  const pub = await crypto.subtle.importKey('raw', Buffer.from(keys.publicKey, 'base64url'), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  assert.ok(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, Buffer.from(s, 'base64url'), te.encode(`${h}.${p}`)))
})

test('normalizeHost', () => {
  assert.equal(util.normalizeHost('HTTPS://GitHub.com/x?y'), 'github.com')
  assert.equal(util.normalizeHost('db.example.com:5432'), 'db.example.com')
  assert.equal(util.normalizeHost(''), null)
  assert.equal(util.normalizeHost('http://'), null)
  assert.notEqual(util.normalizeHost(util.CARD_TARGET), util.CARD_TARGET, 'no host normalises to the card target')
  assert.notEqual(util.normalizeHost('https://@card'), util.CARD_TARGET)
})

// The Workers Free plan allows 10ms of CPU per request. Everything we do per
// request is a handful of native WebCrypto calls; this guards against a
// regression that would push the heaviest paths (push fan-out, passkey login)
// anywhere near that budget. Node and workerd share V8 and BoringSSL.
test('CPU budget: heaviest per-request crypto stays far below 10ms', async () => {
  const sub = await fakeSubscription('https://push.example/x')
  const record = { endpoint: sub.json.endpoint, ...sub.json.keys }
  const vapid = await webpush.generateVapidKeys()
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const passkey = { publicKey: b64url(new Uint8Array(await crypto.subtle.exportKey('spki', keys.publicKey))), alg: -7, signCount: 0 }
  const expected = { challenge: 'abc', origin: 'https://wb.example', rpId: 'wb.example' }
  const assertion = await makeAssertion({ ...expected, keys })
  const N = 50
  const time = async (fn) => {
    await fn()
    const t = performance.now()
    for (let i = 0; i < N; i++) await fn()
    return (performance.now() - t) / N
  }
  const push = await time(async () => {
    await webpush.vapidHeader(`https://p${Math.random()}.example/x`, vapid, 'mailto:a@b.c')
    await webpush.encryptPayload(te.encode('{"title":"x","body":"y"}'), record)
  })
  const login = await time(() => webauthn.verifyAssertion(assertion, passkey, expected))
  const hash = await time(() => util.sha256Hex(util.randomToken()))
  console.log(`    push (uncached VAPID + encrypt): ${push.toFixed(3)}ms · passkey verify: ${login.toFixed(3)}ms · token hash: ${hash.toFixed(3)}ms`)
  assert.ok(push < 3, `push took ${push}ms`)
  assert.ok(login < 3, `passkey verify took ${login}ms`)
})

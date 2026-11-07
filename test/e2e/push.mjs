// Plays the browser's side of Web Push so the test can decrypt what the broker sent (RFC 8291).
const subtle = globalThis.crypto.subtle
const te = new TextEncoder()
const b64url = (u8) => Buffer.from(u8).toString('base64url')
const concat = (...p) => new Uint8Array(Buffer.concat(p.map((x) => Buffer.from(x))))

export async function fakeSubscription(endpoint) {
  const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const pub = new Uint8Array(await subtle.exportKey('raw', pair.publicKey))
  const auth = globalThis.crypto.getRandomValues(new Uint8Array(16))
  return { pair, pub, auth, json: { endpoint, keys: { p256dh: b64url(pub), auth: b64url(auth) } } }
}

async function hkdf(salt, ikm, info, len) {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, len * 8))
}

export async function decryptPush(body, sub) {
  const buf = new Uint8Array(body)
  const salt = buf.slice(0, 16)
  const idlen = buf[20]
  const asPub = buf.slice(21, 21 + idlen)
  const ct = buf.slice(21 + idlen)
  const asKey = await subtle.importKey('raw', asPub, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const secret = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: asKey }, sub.pair.privateKey, 256))
  const ikm = await hkdf(sub.auth, secret, concat(te.encode('WebPush: info\0'), sub.pub, asPub), 32)
  const cek = await hkdf(salt, ikm, te.encode('Content-Encoding: aes128gcm\0'), 16)
  const nonce = await hkdf(salt, ikm, te.encode('Content-Encoding: nonce\0'), 12)
  const key = await subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt'])
  const plain = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct))
  let end = plain.length - 1
  while (end >= 0 && plain[end] === 0) end--
  if (plain[end] !== 2) throw new Error('missing last-record delimiter')
  return new TextDecoder().decode(plain.slice(0, end))
}

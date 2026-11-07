# Decisions to review

These are the calls I made while implementing [SPEC.md](SPEC.md), roughly in order of how much they matter. Each one says
what I chose, why, and what you might want instead.

## Architecture

### 1. The vault is read from Bitwarden's API, through a narrow proxy on the broker

The spec says secrets are "decrypted from Bitwarden" on the phone, but not where the phone gets the encrypted vault. The
reference project reads NodeWarden's D1 database directly. I chose the standard Bitwarden client API instead (`prelogin`,
`connect/token`, `sync`), so WardenBroker works with **bitwarden.com, bitwarden.eu, Vaultwarden and NodeWarden** alike.

Bitwarden's API isn't CORS-enabled for third-party origins, so the PWA calls it through four fixed proxy routes on the
Worker (`worker/bitwarden.ts`). Only the configured `BW_SERVER` is reachable through them, so the Worker can't be used as
an open proxy. Pre-login routes refuse any email other than `OWNER_EMAIL`, and `sync` and `refresh` require a session.

**Trade-off:** the broker sees the master password *hash*, the access and refresh tokens, and the encrypted vault in
transit. It never stores them. It can't decrypt the vault, but a malicious deployment could capture the hash and
brute-force it offline at full KDF cost, which is the same exposure Bitwarden's own server has. If you'd rather the broker
never see even that, the alternative is a NodeWarden-only mode reading D1. That is possible, but it gives up
bitwarden.com support.

**Not verified against the live bitwarden.com:** there were no credentials in this environment. The flow follows the
official web vault (`client_id=web`, `Auth-Email` header, `deviceType=14`, `newDeviceOtp`, 2FA remember tokens), and the
mock server reproduces those behaviours, but Bitwarden may treat requests from Cloudflare IP ranges or unknown client
versions differently. `BW_CLIENT_VERSION` lives in `worker/bitwarden.ts`. **Please do a first real login and tell me if
anything is refused.**

### 2. The broker is one SQLite-backed Durable Object

One owner means one strongly consistent store, and gives a place to park long-polling agents in memory. SQLite-backed
Durable Objects are on the Free plan. The alternatives fell short: KV allows only 1,000 writes a day on the free tier and
is eventually consistent, and D1 has no in-memory place to park waiters. Housekeeping (expiring sessions, grants and
requests; trimming logs to 1,000 rows) runs on every request instead of a cron or alarm, so no extra invocations are used.

### 3. Agents long-poll (answers the spec's open question)

CPU time is not wall time, so waiting costs nothing against the 10 ms limit. `GET /api/agent/requests/:id?wait=25` parks
in the Durable Object and wakes the instant you approve. The CLI loops on 25-second polls, which is safely under
Cloudflare's idle timeouts. The cost is Durable Object *duration*: the Free plan's 13,000 GB-s/day covers about 28 hours of
continuous waiting. I didn't use WebSocket hibernation: it would make duration free, but it's a lot more machinery for a
personal broker.

### 4. Stack: TypeScript Worker, React + Vite PWA, Go CLI

- **Worker in plain TypeScript, no framework.** I considered Go (TinyGo to WASM) and Rust: WASM instantiation and the JS
  boundary cost more CPU per request than V8 running JS that mostly calls native WebCrypto. The Worker is about 11 KB
  gzipped.
- **PWA in React and Vite**, as the spec suggested. The only runtime dependency beyond React is `hash-wasm`, for Argon2id
  accounts; it is lazy-loaded.
- **CLI in Go, standard library only.** That's possible because Go 1.24 added `crypto/hkdf`. It ships as one static binary.

## Cryptography

### 5. Agent encryption: ECIES with P-256, HKDF-SHA256 and AES-256-GCM, bound to the host

I chose P-256 over X25519 because WebCrypto supports it on every phone browser (X25519 support in WebCrypto is newer), and
Go's `crypto/ecdh` handles it natively. The requested host is bound in as AES-GCM associated data, and the CLI also checks
the host inside the payload. That stops a malicious broker from answering a request for host B with a secret approved for
host A.

### 6. The passkey protects the user key, not the master password

The spec asked whether a passkey could encrypt the master password and store it locally. **It can, via the WebAuthn PRF
extension.** I store the 64-byte Bitwarden *user key* plus a refresh token instead, encrypted with AES-GCM under
HKDF(PRF output). That is equally capable for our purposes, but:

- unlocking doesn't re-run the KDF, so it's instant even with heavy Argon2 settings;
- the master password, which unlocks your Bitwarden *account* everywhere, is never written down anywhere.

When the refresh token expires, which takes weeks, the app tells you to sign in with the master password once.

### 7. The passkey is also the broker login

A single WebAuthn ceremony both signs you in to the broker (verified server-side) and returns the PRF secret that unlocks
the vault. Registration trusts the browser's `getPublicKey()` rather than parsing CBOR attestation. That's safe here because
registering a passkey requires an existing session. Assertions are fully verified: challenge, origin, RP ID hash, UP and UV
flags, the signature, and the sign counter.

### 8. Signing in with the master password signs you in to the broker

There's no separate broker password. The broker considers you the owner when Bitwarden accepts a password login for
`OWNER_EMAIL`, including 2FA, as seen through the proxy. That's how the spec's "user authenticates with the Bitwarden
master password" becomes broker authentication too. **`OWNER_EMAIL` is required**: I didn't want a "first person to log in
claims the broker" race on a public URL.

### 9. Push payloads are encrypted (RFC 8291)

The reference project sends empty pushes and has the service worker fetch details. That fails once the session has expired,
which is the common case on a phone. Encrypting the payload makes the notification text work on a locked phone. The text
only carries the agent name, the host and the reason. **It appears on your lock screen.** If you'd rather show a generic
"Something needs your approval", that's a one-line change in `worker/broker.ts` (`notify` calls).

## Product behaviour

### 10. What gets shared, and how it's chosen

- The whole item is sealed to the agent: username, password, TOTP seed, URIs, notes and custom fields. Agents often need
  more than the password (an API key in a custom field, or a TOTP code), and asking again for each field would be
  annoying. The approval card lists exactly which fields are shared.
- **Host matching** follows Bitwarden's URI match types (domain, host, regex, never). A best-tier match is picked
  automatically only when it's unique; otherwise you pick, from the candidates or from a search. "Registrable domain" uses
  a small list of common second-level suffixes (`co.uk`, `com.au`, …) rather than the full Public Suffix List, to keep the
  bundle small.
- **TOTP codes are computed on the agent** from the seed, so they work for the whole grant duration.

### 11. Durations: Once, 1 hour (default), 1 day, 1 week, Always

The spec says "a given amount of time, or permanently". I added **Once** (no stored grant) and made **1 hour** the
default, because agents tend to need the same credential several times during one task. Grants are keyed by
(agent, host). A grant is a *snapshot*: if you change the password in Bitwarden, revoke the grant and the agent will ask
again.

### 12. The broker hands over ciphertext once

A delivered request has its ciphertext wiped. Answered requests lose their ciphertext after at most an hour even if never
collected, and request rows are deleted after 7 days. Grants keep their own copy until they expire or are revoked.

### 13. The UI really is just two screens

When something is pending, you see **one** approval card, with a "N waiting" counter. Otherwise you see **Agents** (tap one
for its fingerprint, active grants with *Revoke*, and *Disconnect*) and **Activity**. Grant management sits inside the
agent row, so the spec's "connected agents and logs, nothing else" still holds.

### 14. PWA-only, with a localhost exception

Outside an installed app, the PWA shows install instructions, as the spec requires. On `localhost` and `127.0.0.1` it runs
in a tab so development and the e2e suite work. The app also locks itself after 5 minutes in the background, and every cold
start needs the passkey.

### 15. Limits and abuse controls

- Agent registration has to be unauthenticated, so it is capped at 10 pending agents and 20 registrations per hour.
- Each agent may have at most 5 pending requests, and duplicate requests for the same host are merged.
- Requests expire after 10 minutes; the CLI also waits 10 minutes by default.
- Reasons are required and limited to 500 characters. Ciphertexts are limited to 64 KB.

### 16. Metadata the broker keeps

Item **names** appear in the activity log ("Shared github.com with build-box · GitHub · 1h"). That makes the log useful. It
is metadata, not a secret, but if you consider item names sensitive, stop sending `itemName` in the approve call.

## Not implemented (deliberately)

- **Browser autofill**, which the spec ruled out.
- **2FA via security key, Duo or WebAuthn on the Bitwarden account.** Authenticator apps and email codes work. Other
  methods get a clear message asking you to add one of those.
- **Key rotation of the Bitwarden user key while a passkey blob exists.** If you rotate your account encryption key, sign
  in with the master password once and re-link the passkey (the app offers this).
- **Multiple owners.** One deployment serves one Bitwarden account.

## Test-only switch

`DEV_ALLOW_INSECURE_PUSH=1` lets the e2e suite point a push subscription at a local `http://` mock push service, so it can
decrypt real notifications. **Never set it in production.** It is not in `wrangler.jsonc`.

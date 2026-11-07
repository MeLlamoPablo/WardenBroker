import { useState, type FormEvent } from 'react'
import type { Config } from './App'
import { loginChallenge, sendEmailCode, type LoginChallenge } from './bw'
import { completeLogin, prepareLogin, rememberedEmail, type PreparedLogin, type Session } from './vault'
import { ErrorText, errorMessage, Logo } from './ui'

const PROVIDER_AUTHENTICATOR = 0
const PROVIDER_EMAIL = 1

export function Login({ config, onDone }: { config: Config | null; onDone: (s: Session) => void }) {
  const [email, setEmail] = useState(rememberedEmail())
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [prep, setPrep] = useState<PreparedLogin | null>(null)
  const [challenge, setChallenge] = useState<LoginChallenge | null>(null)
  const [code, setCode] = useState('')
  const [emailSent, setEmailSent] = useState(false)

  const provider = challenge?.providers?.includes(PROVIDER_AUTHENTICATOR)
    ? PROVIDER_AUTHENTICATOR
    : challenge?.providers?.includes(PROVIDER_EMAIL)
      ? PROVIDER_EMAIL
      : null

  async function attempt(p: PreparedLogin, extra: Record<string, string>) {
    try {
      onDone(await completeLogin(p, extra))
    } catch (err) {
      const c = loginChallenge(err)
      if (c && (!challenge || c.kind !== challenge.kind)) {
        setChallenge(c)
        setCode('')
      } else setError(errorMessage(err))
    }
  }

  async function submitPassword(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const p = await prepareLogin(email, password)
      setPrep(p)
      setPassword('')
      await attempt(p, {})
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault()
    if (!prep || !challenge) return
    setBusy(true)
    setError(null)
    const extra: Record<string, string> =
      challenge.kind === 'new-device'
        ? { newDeviceOtp: code.trim() }
        : { twoFactorToken: code.replace(/\s/g, ''), twoFactorProvider: String(provider), twoFactorRemember: '1' }
    await attempt(prep, extra)
    setBusy(false)
  }

  async function sendEmail() {
    if (!prep) return
    setError(null)
    try {
      await sendEmailCode(prep.email, prep.hash)
      setEmailSent(true)
    } catch (err) {
      setError(errorMessage(err))
    }
  }

  if (challenge && prep) {
    const unsupported = challenge.kind === 'two-factor' && provider === null
    return (
      <div className="screen center">
        <form className="stack narrow" onSubmit={submitCode}>
          <Logo />
          <h1>{challenge.kind === 'new-device' ? 'Verify this device' : 'Two-step login'}</h1>
          {challenge.kind === 'new-device' && <p className="muted">Bitwarden emailed a verification code to {prep.email}.</p>}
          {provider === PROVIDER_AUTHENTICATOR && <p className="muted">Enter the code from your authenticator app.</p>}
          {provider === PROVIDER_EMAIL && (
            <p className="muted">
              Enter the code Bitwarden emails you.{' '}
              <button type="button" className="link" onClick={sendEmail}>
                {emailSent ? 'Send again' : 'Send code'}
              </button>
            </p>
          )}
          {unsupported ? (
            <p className="error">
              Your account only offers two-step methods WardenBroker can't use yet (security key, Duo). Add an authenticator app or email
              method in Bitwarden.
            </p>
          ) : (
            <>
              <input
                className="code"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                autoFocus
                required
              />
              <ErrorText error={error} />
              <button className="primary" disabled={busy || !code.trim()}>
                {busy ? 'Verifying…' : 'Continue'}
              </button>
            </>
          )}
          <button
            type="button"
            className="link"
            onClick={() => {
              setChallenge(null)
              setPrep(null)
              setError(null)
            }}
          >
            Back
          </button>
        </form>
      </div>
    )
  }

  return (
    <div className="screen center">
      <form className="stack narrow" onSubmit={submitPassword}>
        <Logo />
        <h1>Sign in with Bitwarden</h1>
        <p className="muted">
          Your master password never leaves this device. It unlocks your vault here, so secrets can be encrypted straight to your agents.
        </p>
        <label>
          Email
          <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </label>
        <label>
          Master password
          <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        <ErrorText error={error} />
        <button className="primary" disabled={busy}>
          {busy ? 'Unlocking…' : 'Sign in'}
        </button>
        {config?.bwServer && <p className="fine">Server: {new URL(config.bwServer).host}</p>}
      </form>
    </div>
  )
}

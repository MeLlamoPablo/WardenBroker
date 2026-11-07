import { useState } from 'react'
import type { Config } from './App'
import { passkeysAvailable } from './passkey'
import { currentSubscription, enablePush, pushSupported } from './push'
import { enablePasskey, lockBlob, PrfUnsupportedError, type Session } from './vault'
import { ErrorText, errorMessage, Logo } from './ui'

export async function needsSetup(s: Session, config: Config | null): Promise<boolean> {
  const wantsPasskey = passkeysAvailable() && (!lockBlob() || !s.lockKey)
  const wantsPush = pushSupported() && !!config && !(await currentSubscription().catch(() => null))
  return wantsPasskey || wantsPush
}

export function Setup({ session, config, onDone }: { session: Session; config: Config | null; onDone: () => void }) {
  const [step, setStep] = useState<'passkey' | 'push'>(passkeysAvailable() ? 'passkey' : 'push')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function next() {
    setError(null)
    if (step === 'passkey' && pushSupported() && config && !(await currentSubscription().catch(() => null))) setStep('push')
    else onDone()
  }

  async function doPasskey() {
    setBusy(true)
    setError(null)
    try {
      await enablePasskey(session)
      await next()
    } catch (err) {
      setError(errorMessage(err))
      if (err instanceof PrfUnsupportedError) setTimeout(next, 4000)
    } finally {
      setBusy(false)
    }
  }

  async function doPush() {
    setBusy(true)
    setError(null)
    try {
      await enablePush(config!.vapidPublicKey)
      onDone()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="screen center">
      <div className="stack narrow">
        <Logo />
        {step === 'passkey' ? (
          <>
            <h1>Unlock with a passkey</h1>
            <p className="muted">
              Create a passkey so you can approve requests with Face ID or your fingerprint. Your vault key is encrypted on this device
              with a secret only that passkey can produce.
            </p>
            <button className="primary" onClick={doPasskey} disabled={busy}>
              {busy ? 'Waiting for passkey…' : lockBlob() ? 'Re-link passkey' : 'Create passkey'}
            </button>
          </>
        ) : (
          <>
            <h1>Turn on notifications</h1>
            <p className="muted">Get a notification the moment an agent asks for a secret or wants to connect.</p>
            <button className="primary" onClick={doPush} disabled={busy}>
              {busy ? 'Enabling…' : 'Enable notifications'}
            </button>
          </>
        )}
        <ErrorText error={error} />
        <button className="link" onClick={next}>
          Not now
        </button>
      </div>
    </div>
  )
}

import { useState } from 'react'
import { unlockWithPasskey, type Session } from './vault'
import { ErrorText, errorMessage, Logo } from './ui'

export function Locked({ onDone, onUsePassword }: { onDone: (s: Session) => void; onUsePassword: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  async function unlock() {
    setBusy(true)
    setError(null)
    try {
      onDone(await unlockWithPasskey())
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="screen center">
      <div className="stack narrow">
        <Logo size={72} />
        <h1>WardenBroker is locked</h1>
        <button className="primary big" onClick={unlock} disabled={busy}>
          {busy ? 'Unlocking…' : 'Unlock with passkey'}
        </button>
        <ErrorText error={error} />
        <button className="link" onClick={onUsePassword}>
          Use master password instead
        </button>
      </div>
    </div>
  )
}

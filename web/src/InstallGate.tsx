import { useEffect, useState } from 'react'
import { Logo } from './ui'

/** WardenBroker only runs installed: push on iOS needs it, and it keeps the vault key out of browser tabs. */
export function isStandalone(): boolean {
  if (window.matchMedia('(display-mode: standalone)').matches) return true
  if ((navigator as any).standalone === true) return true
  // Local development (wrangler dev, tests) runs in a normal tab.
  return ['localhost', '127.0.0.1'].includes(location.hostname)
}

export function InstallGate() {
  const [prompt, setPrompt] = useState<any>(null)
  useEffect(() => {
    const handler = (e: Event) => {
      e.preventDefault()
      setPrompt(e)
    }
    window.addEventListener('beforeinstallprompt', handler)
    return () => window.removeEventListener('beforeinstallprompt', handler)
  }, [])
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent)
  return (
    <div className="screen center">
      <div className="stack narrow">
        <Logo />
        <h1>Install WardenBroker</h1>
        <p className="muted">
          WardenBroker only runs as an installed app, so it can deliver approval notifications and keep your vault key away from browser tabs.
        </p>
        {prompt ? (
          <button className="primary" onClick={() => prompt.prompt()}>
            Install app
          </button>
        ) : ios ? (
          <ol className="steps">
            <li>Tap the <b>Share</b> button in Safari</li>
            <li>Choose <b>Add to Home Screen</b></li>
            <li>Open WardenBroker from your home screen</li>
          </ol>
        ) : (
          <ol className="steps">
            <li>Open your browser menu</li>
            <li>Choose <b>Install app</b> or <b>Add to Home screen</b></li>
            <li>Open WardenBroker from your home screen</li>
          </ol>
        )}
      </div>
    </div>
  )
}

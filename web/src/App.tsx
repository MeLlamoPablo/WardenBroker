import { useCallback, useEffect, useRef, useState } from 'react'
import { api, setUnauthorizedHandler } from './api'
import { Home } from './Home'
import { InstallGate, isStandalone } from './InstallGate'
import { Login } from './Login'
import { Locked } from './Locked'
import { Setup, needsSetup } from './Setup'
import { lockBlob, refreshVault, type Session } from './vault'

export interface Config {
  vapidPublicKey: string
  hasPasskeys: boolean
  bwServer: string
}

type Screen = 'loading' | 'install' | 'login' | 'locked' | 'setup' | 'home'

const AUTO_LOCK_MS = 5 * 60 * 1000

export function App() {
  const [config, setConfig] = useState<Config | null>(null)
  const [screen, setScreen] = useState<Screen>('loading')
  const [session, setSession] = useState<Session | null>(null)
  const [, setTick] = useState(0)
  const hiddenAt = useRef<number | null>(null)

  const lock = useCallback(() => {
    setSession(null)
    setScreen(lockBlob() ? 'locked' : 'login')
  }, [])

  useEffect(() => {
    setUnauthorizedHandler(lock)
    return () => setUnauthorizedHandler(null)
  }, [lock])

  useEffect(() => {
    if (!isStandalone()) {
      setScreen('install')
      return
    }
    api<Config>('/api/config')
      .then((c) => {
        setConfig(c)
        setScreen(lockBlob() ? 'locked' : 'login')
      })
      .catch(() => setScreen('login'))
  }, [])

  // Forget the decrypted vault when the app sits in the background.
  useEffect(() => {
    const onVisibility = () => {
      if (document.hidden) hiddenAt.current = Date.now()
      else if (hiddenAt.current && Date.now() - hiddenAt.current > AUTO_LOCK_MS && session) lock()
    }
    document.addEventListener('visibilitychange', onVisibility)
    return () => document.removeEventListener('visibilitychange', onVisibility)
  }, [session, lock])

  const onUnlocked = useCallback(
    async (s: Session, viaPassword: boolean) => {
      setSession(s)
      setScreen(viaPassword && (await needsSetup(s, config)) ? 'setup' : 'home')
      if (!viaPassword) {
        // Show the cached vault right away, refresh it behind the scenes.
        refreshVault(s).then(() => setTick((t) => t + 1))
      }
    },
    [config],
  )

  if (screen === 'loading') return <div className="screen center"><div className="spinner" /></div>
  if (screen === 'install') return <InstallGate />
  if (screen === 'login') return <Login config={config} onDone={(s) => onUnlocked(s, true)} />
  if (screen === 'locked') return <Locked onDone={(s) => onUnlocked(s, false)} onUsePassword={() => setScreen('login')} />
  if (screen === 'setup' && session) return <Setup session={session} config={config} onDone={() => setScreen('home')} />
  if (screen === 'home' && session)
    return (
      <Home
        session={session}
        config={config}
        onLock={async () => {
          await api('/api/auth/logout', { method: 'POST', body: {} }).catch(() => {})
          lock()
        }}
        onVaultChanged={() => refreshVault(session).then(() => setTick((t) => t + 1))}
      />
    )
  return null
}

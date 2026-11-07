import type { ReactNode } from 'react'

export function Logo({ size = 56 }: { size?: number }) {
  return <img src="/icon.svg" width={size} height={size} alt="" className="logo" />
}

export function ErrorText({ error }: { error: string | null }) {
  if (!error) return null
  return (
    <p className="error" role="alert">
      {error}
    </p>
  )
}

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <section className={`card ${className}`}>{children}</section>
}

export function ago(ts: number | null | undefined): string {
  if (!ts) return 'never'
  const s = Math.round((Date.now() - ts) / 1000)
  if (s < 0) return 'just now'
  if (s < 45) return 'just now'
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  if (s < 86400) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

export function until(ts: number | null | undefined): string {
  if (ts === null || ts === undefined) return 'until revoked'
  const s = Math.round((ts - Date.now()) / 1000)
  if (s <= 0) return 'expired'
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m left`
  if (s < 86400) return `${Math.round(s / 3600)}h left`
  return `${Math.round(s / 86400)}d left`
}

export function errorMessage(err: unknown): string {
  if (err instanceof DOMException && err.name === 'NotAllowedError') return 'The passkey prompt was cancelled or timed out.'
  return (err as Error)?.message || String(err)
}

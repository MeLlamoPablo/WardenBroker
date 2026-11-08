import { useCallback, useEffect, useMemo, useState } from 'react'
import type { Config } from './App'
import { api, CARD_TARGET, describeTarget, type Agent, type AppState, type LogEntry, type PendingRequest } from './api'
import { candidatesFor, cardCandidates, type VaultItem } from './bw'
import { utf8 } from './bytes'
import { currentSubscription, enablePush, pushSupported } from './push'
import { seal } from './seal'
import { ago, Card, ErrorText, errorMessage, Logo, until } from './ui'
import type { Session } from './vault'

const POLL_MS = 4000

export function Home({
  session,
  config,
  onLock,
  onVaultChanged,
}: {
  session: Session
  config: Config | null
  onLock: () => void
  onVaultChanged: () => void
}) {
  const [state, setState] = useState<AppState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pushOn, setPushOn] = useState<boolean | null>(null)

  const load = useCallback(async () => {
    try {
      setState(await api<AppState>('/api/app/state'))
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
    }
  }, [])

  useEffect(() => {
    load()
    const timer = setInterval(() => !document.hidden && load(), POLL_MS)
    const onMessage = (e: MessageEvent) => e.data?.type === 'wardenbroker:refresh' && load()
    const onVisible = () => !document.hidden && load()
    navigator.serviceWorker?.addEventListener('message', onMessage)
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      clearInterval(timer)
      navigator.serviceWorker?.removeEventListener('message', onMessage)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [load])

  useEffect(() => {
    currentSubscription()
      .then((s) => setPushOn(!!s))
      .catch(() => setPushOn(false))
  }, [])

  const pendingCount = state ? state.pendingAgents.length + state.pendingRequests.length : 0
  useEffect(() => {
    const nav = navigator as any
    if (pendingCount) nav.setAppBadge?.(pendingCount).catch?.(() => {})
    else nav.clearAppBadge?.().catch?.(() => {})
  }, [pendingCount])

  const pendingAgent = state?.pendingAgents[0]
  const pendingRequest = state?.pendingRequests[0]

  return (
    <div className="screen">
      <header className="topbar">
        <div className="brand">
          <Logo size={28} />
          <span>WardenBroker</span>
        </div>
        <button className="ghost" onClick={onLock} aria-label="Lock">
          Lock
        </button>
      </header>
      <main className="content">
        <ErrorText error={error} />
        {!state ? (
          <div className="center pad">
            <div className="spinner" />
          </div>
        ) : pendingAgent ? (
          <AgentApproval key={pendingAgent.id} agent={pendingAgent} remaining={pendingCount} onDone={load} />
        ) : pendingRequest ? (
          <SecretApproval key={pendingRequest.id} request={pendingRequest} session={session} remaining={pendingCount} onDone={load} />
        ) : (
          <>
            {pushOn === false && pushSupported() && config && (
              <button
                className="banner"
                onClick={async () => {
                  try {
                    await enablePush(config.vapidPublicKey)
                    setPushOn(true)
                  } catch (err) {
                    setError(errorMessage(err))
                  }
                }}
              >
                Notifications are off — tap to enable
              </button>
            )}
            {session.syncError && (
              <p className="banner warn" role="status">
                {session.syncError}
              </p>
            )}
            <Agents agents={state.agents} onChange={load} />
            <Logs logs={state.logs} />
            <p className="fine center-text">
              {session.items.length} vault items · {session.syncedAt ? `synced ${ago(session.syncedAt)}` : 'cached vault'}
              {' · '}
              <button className="link small" onClick={onVaultChanged}>
                refresh
              </button>
            </p>
          </>
        )}
      </main>
    </div>
  )
}

// ------------------------------------------------------------ approvals

function Fingerprint({ value }: { value: string }) {
  return <code className="fingerprint">{value}</code>
}

function AgentApproval({ agent, remaining, onDone }: { agent: Agent; remaining: number; onDone: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  async function act(action: 'approve' | 'deny') {
    setBusy(true)
    setError(null)
    try {
      await api(`/api/app/agents/${agent.id}/${action}`, { method: 'POST', body: {} })
      onDone()
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }
  return (
    <Card className="approval">
      <p className="eyebrow">New agent{remaining > 1 ? ` · ${remaining} waiting` : ''}</p>
      <h2>{agent.name}</h2>
      <p className="muted">wants to connect to your broker. Check that the fingerprint matches what the agent's terminal shows.</p>
      <Fingerprint value={agent.fingerprint} />
      <p className="fine">Requested {ago(agent.created_at)}</p>
      <ErrorText error={error} />
      <div className="actions">
        <button className="secondary" disabled={busy} onClick={() => act('deny')}>
          Deny
        </button>
        <button className="primary" disabled={busy} onClick={() => act('approve')}>
          Connect
        </button>
      </div>
    </Card>
  )
}

const DURATIONS = [
  { label: '5 min', value: 300 },
  { label: '1 hour', value: 3600 },
  { label: '1 day', value: 86400 },
  { label: '1 week', value: 7 * 86400 },
  { label: 'Always', value: -1 },
]

function sharedFields(item: VaultItem): string[] {
  const out: string[] = []
  if (item.card) {
    if (item.card.number) out.push('card number')
    if (item.card.cardholderName) out.push('cardholder')
    if (item.card.expMonth || item.card.expYear) out.push('expiry')
    if (item.card.code) out.push('security code')
  }
  if (item.username) out.push('username')
  if (item.password) out.push('password')
  if (item.totp) out.push('TOTP seed')
  if (item.fields.length) out.push(`${item.fields.length} custom field${item.fields.length > 1 ? 's' : ''}`)
  if (item.notes) out.push('notes')
  return out
}

function cardSummary(card: NonNullable<VaultItem['card']>): string {
  const last4 = card.number.replace(/\D/g, '').slice(-4)
  return [card.brand || 'Card', last4 && `•••• ${last4}`].filter(Boolean).join(' ')
}

function ItemRow({ item, selected, onSelect }: { item: VaultItem; selected: boolean; onSelect: () => void }) {
  return (
    <button type="button" className={`item ${selected ? 'selected' : ''}`} onClick={onSelect} aria-pressed={selected}>
      <span className="item-name">{item.name || '(no name)'}</span>
      <span className="item-meta">
        {(item.card && cardSummary(item.card)) || item.username || item.uris[0]?.uri || ' '}
        {item.organization ? ` · ${item.organization}` : ''}
      </span>
    </button>
  )
}

function SecretApproval({
  request,
  session,
  remaining,
  onDone,
}: {
  request: PendingRequest
  session: Session
  remaining: number
  onDone: () => void
}) {
  const isCard = request.host === CARD_TARGET
  // Cards are never matched to a host: list them all and always make the user pick.
  const { items: candidates, autoPick } = useMemo(
    () => (isCard ? { items: cardCandidates(session.items), autoPick: null } : candidatesFor(session.items, request.host)),
    [isCard, session.items, request.host],
  )
  const [selectedId, setSelectedId] = useState<string | null>(autoPick?.id ?? null)
  const [picking, setPicking] = useState(!autoPick)
  const [query, setQuery] = useState('')
  const [duration, setDuration] = useState(3600)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const selected = session.items.find((i) => i.id === selectedId) || null
  const searchResults = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return candidates
    return session.items
      .filter((i) => i.name.toLowerCase().includes(q) || i.username.toLowerCase().includes(q) || i.uris.some((u) => u.uri.toLowerCase().includes(q)))
      .slice(0, 50)
  }, [query, candidates, session.items])

  async function approve() {
    if (!selected) return
    setBusy(true)
    setError(null)
    try {
      const payload = {
        v: 1,
        host: request.host,
        item: {
          id: selected.id,
          name: selected.name,
          username: selected.username,
          password: selected.password,
          totp: selected.totp,
          uris: selected.uris.map((u) => u.uri),
          notes: selected.notes,
          fields: selected.fields,
          ...(selected.card ? { card: selected.card } : {}),
        },
        approvedAt: Date.now(),
      }
      const ciphertext = await seal(request.public_key, request.host, utf8(JSON.stringify(payload)))
      await api(`/api/app/requests/${request.id}/approve`, { method: 'POST', body: { ciphertext, itemName: selected.name, duration } })
      onDone()
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  async function deny() {
    setBusy(true)
    try {
      await api(`/api/app/requests/${request.id}/deny`, { method: 'POST', body: {} })
      onDone()
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  return (
    <Card className="approval">
      <p className="eyebrow">
        {isCard ? 'Card request' : 'Secret request'}
        {remaining > 1 ? ` · ${remaining} waiting` : ''} · {until(request.expires_at)}
      </p>
      <h2 className="host">{isCard ? 'Payment card' : request.host}</h2>
      <p className="requester">
        <b>{request.agent_name}</b> <Fingerprint value={request.fingerprint} />
      </p>
      <blockquote className="reason">{request.reason}</blockquote>

      {selected && !picking ? (
        <div className="picked">
          <ItemRow item={selected} selected onSelect={() => setPicking(true)} />
          <p className="fine">Shares {sharedFields(selected).join(', ') || 'nothing'} · <button className="link small" onClick={() => setPicking(true)}>change</button></p>
        </div>
      ) : (
        <div className="picker">
          <p className="muted">
            {isCard
              ? candidates.length === 0
                ? 'No cards in your vault. Search for an item:'
                : 'Pick a card to share:'
              : candidates.length === 0
              ? `No vault item matches ${request.host}. Search for one:`
              : candidates.length > 1
                ? `${candidates.length} items match. Pick one:`
                : 'Pick an item:'}
          </p>
          <input type="search" placeholder="Search vault" value={query} onChange={(e) => setQuery(e.target.value)} />
          <div className="item-list">
            {searchResults.map((item) => (
              <ItemRow
                key={item.id}
                item={item}
                selected={item.id === selectedId}
                onSelect={() => {
                  setSelectedId(item.id)
                  setPicking(false)
                }}
              />
            ))}
            {query && searchResults.length === 0 && <p className="fine">Nothing found.</p>}
          </div>
        </div>
      )}

      <div className="segmented" role="radiogroup" aria-label="Access duration">
        {DURATIONS.map((d) => (
          <button key={d.value} role="radio" aria-checked={duration === d.value} className={duration === d.value ? 'on' : ''} onClick={() => setDuration(d.value)}>
            {d.label}
          </button>
        ))}
      </div>
      <ErrorText error={error} />
      <div className="actions">
        <button className="secondary" disabled={busy} onClick={deny}>
          Deny
        </button>
        <button className="primary" disabled={busy || !selected} onClick={approve}>
          {busy ? 'Encrypting…' : 'Approve'}
        </button>
      </div>
    </Card>
  )
}

// ---------------------------------------------------------------- agents

function Agents({ agents, onChange }: { agents: Agent[]; onChange: () => void }) {
  const [open, setOpen] = useState<string | null>(null)
  return (
    <section>
      <h3 className="section-title">Agents</h3>
      {agents.length === 0 ? (
        <Card>
          <p className="muted">No agents yet. On the machine running your agent:</p>
          <pre className="cmd">wardenbroker register --url {location.origin} --name my-agent</pre>
          <p className="fine">You'll get a notification here to approve it.</p>
        </Card>
      ) : (
        <div className="list">
          {agents.map((a) => (
            <AgentRow key={a.id} agent={a} open={open === a.id} onToggle={() => setOpen(open === a.id ? null : a.id)} onChange={onChange} />
          ))}
        </div>
      )}
    </section>
  )
}

function AgentRow({ agent, open, onToggle, onChange }: { agent: Agent; open: boolean; onToggle: () => void; onChange: () => void }) {
  const [error, setError] = useState<string | null>(null)
  async function call(path: string) {
    setError(null)
    try {
      await api(path, { method: 'DELETE' })
      onChange()
    } catch (err) {
      setError(errorMessage(err))
    }
  }
  const recent = agent.last_seen_at && Date.now() - agent.last_seen_at < 10 * 60 * 1000
  return (
    <div className={`row ${open ? 'open' : ''}`}>
      <button className="row-head" onClick={onToggle} aria-expanded={open}>
        <span className={`dot ${recent ? 'live' : ''}`} />
        <span className="row-title">{agent.name}</span>
        <span className="row-meta">
          {agent.grants.length ? `${agent.grants.length} grant${agent.grants.length > 1 ? 's' : ''} · ` : ''}
          {ago(agent.last_seen_at)}
        </span>
      </button>
      {open && (
        <div className="row-body">
          <p className="fine">
            Fingerprint <Fingerprint value={agent.fingerprint} /> · connected {ago(agent.approved_at)}
          </p>
          {agent.grants.length === 0 ? (
            <p className="fine">No standing access. Every request asks you first.</p>
          ) : (
            <ul className="grants">
              {agent.grants.map((g) => (
                <li key={g.id}>
                  <div>
                    <b>{g.host === CARD_TARGET ? 'Payment card' : g.host}</b> → {g.item_name}
                    <div className="fine">
                      {until(g.expires_at)} · used {g.uses}×{g.last_used_at ? `, last ${ago(g.last_used_at)}` : ''}
                    </div>
                  </div>
                  <button className="ghost danger" onClick={() => call(`/api/app/grants/${g.id}`)}>
                    Revoke
                  </button>
                </li>
              ))}
            </ul>
          )}
          <ErrorText error={error} />
          <button
            className="secondary danger full"
            onClick={() => confirm(`Disconnect ${agent.name}? It will have to register again.`) && call(`/api/app/agents/${agent.id}`)}
          >
            Disconnect agent
          </button>
        </div>
      )}
    </div>
  )
}

// ------------------------------------------------------------------ logs

function describe(log: LogEntry): { text: string; tone: string } {
  const a = log.agent_name || 'Agent'
  const t = describeTarget(log.host)
  switch (log.event) {
    case 'agent.registered':
      return { text: `${a} asked to connect`, tone: 'info' }
    case 'agent.approved':
      return { text: `${a} connected`, tone: 'ok' }
    case 'agent.denied':
      return { text: `${a} was denied`, tone: 'bad' }
    case 'agent.revoked':
      return { text: `${a} was disconnected`, tone: 'bad' }
    case 'secret.requested':
      return { text: `${a} asked for ${t}`, tone: 'info' }
    case 'secret.approved':
      return { text: `Shared ${t} with ${a}`, tone: 'ok' }
    case 'secret.denied':
      return { text: `Denied ${t} to ${a}`, tone: 'bad' }
    case 'secret.served':
      return { text: `${a} used its access to ${t}`, tone: 'ok' }
    case 'grant.revoked':
      return { text: `Revoked ${a}'s access to ${t}`, tone: 'bad' }
    case 'login':
      return { text: 'Signed in', tone: 'muted' }
    case 'passkey.added':
      return { text: 'Passkey added', tone: 'muted' }
    default:
      return { text: log.event, tone: 'muted' }
  }
}

function Logs({ logs }: { logs: LogEntry[] }) {
  const [all, setAll] = useState(false)
  const shown = all ? logs : logs.slice(0, 25)
  return (
    <section>
      <h3 className="section-title">Activity</h3>
      {logs.length === 0 ? (
        <p className="fine">Nothing yet.</p>
      ) : (
        <ul className="logs">
          {shown.map((log) => {
            const d = describe(log)
            return (
              <li key={log.id} className={`log ${d.tone}`}>
                <span className="log-text">{d.text}</span>
                <span className="log-time">{ago(log.ts)}</span>
                {log.detail && <span className="log-detail">{log.detail}</span>}
              </li>
            )
          })}
        </ul>
      )}
      {logs.length > 25 && !all && (
        <button className="link small" onClick={() => setAll(true)}>
          Show all
        </button>
      )}
    </section>
  )
}

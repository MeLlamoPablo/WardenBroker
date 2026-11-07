import { Broker, type Env } from './broker'

export { Broker }

const SECURITY_HEADERS: Record<string, string> = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url)
    if (url.pathname.startsWith('/api/')) {
      // A single named instance: one owner, one broker.
      const stub = env.BROKER.get(env.BROKER.idFromName('broker'))
      const res = await stub.fetch(req)
      const out = new Response(res.body, res)
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v)
      return out
    }
    return env.ASSETS.fetch(req)
  },
} satisfies ExportedHandler<Env>

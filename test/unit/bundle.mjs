// Bundles a TypeScript module from the repo so node:test can import it.
import { build } from 'esbuild'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const dir = mkdtempSync(join(tmpdir(), 'wb-unit-'))
const root = new URL('../../', import.meta.url).pathname

export async function load(entry) {
  const outfile = join(dir, entry.replace(/[\/.]/g, '_') + '.mjs')
  await build({
    entryPoints: [join(root, entry)],
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    outfile,
    external: ['cloudflare:workers', 'hash-wasm'],
    logLevel: 'silent',
  })
  return import(outfile)
}

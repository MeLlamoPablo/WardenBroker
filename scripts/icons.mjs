// Renders web/public/icon.svg into the PNG sizes iOS/Android want.
// Usage: node scripts/icons.mjs  (needs Playwright's Chromium)
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
let playwright
try { playwright = require('playwright') } catch { playwright = require('/opt/node-tools/node_modules/playwright') }

const svg = readFileSync(new URL('../web/public/icon.svg', import.meta.url), 'utf8')
const browser = await playwright.chromium.launch()
const page = await browser.newPage()
const targets = [
  ['icon-192.png', 192, false],
  ['icon-512.png', 512, false],
  ['apple-touch-icon.png', 180, true],
  ['icon-maskable-512.png', 512, true],
]
for (const [name, size, fullBleed] of targets) {
  await page.setViewportSize({ width: size, height: size })
  const inner = fullBleed ? svg.replace('rx="112"', 'rx="0"') : svg
  await page.setContent(`<html><body style="margin:0;background:transparent">${inner.replace('<svg ', `<svg width="${size}" height="${size}" `)}</body></html>`)
  await page.screenshot({ path: new URL(`../web/public/${name}`, import.meta.url).pathname, omitBackground: true })
}
await browser.close()
console.log('icons written')

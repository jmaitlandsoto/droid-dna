#!/usr/bin/env node
// Starts the REA MCP server with the JDK and JADX bridge provisioned.
// Usage: launch.mjs rea
import { spawn } from 'node:child_process'
import { ensureToolchain } from '../lib/toolchain.mjs'

const [major, minor] = process.versions.node.split('.').map(Number)
if (major < 22 || (major === 22 && minor < 19)) {
  console.error(`[readroid] REA needs Node 22.19 or newer; this is ${process.versions.node}.`)
  process.exit(1)
}

const REA_VERSION = '6.5.0'
let env
try {
  env = await ensureToolchain()
} catch (e) {
  console.error('[readroid] toolchain setup failed:', e.message)
  process.exit(1)
}
const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx'
const child = spawn(npx, ['-y', `rea-agents@${REA_VERSION}`, 'mcp'], {
  stdio: 'inherit',
  env: { ...process.env, ...env },
})
child.on('exit', (code, sig) => process.exit(code ?? (sig ? 1 : 0)))
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => child.kill(s))

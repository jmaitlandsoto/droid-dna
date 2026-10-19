#!/usr/bin/env node
// One-time setup: provisions the toolchain and the config dir.
// Usage: node droid-dna/bin/setup.mjs [--check]
import { chmodSync, copyFileSync, existsSync, readFileSync, renameSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { HOME, ENV_FILE, JDK_DIR, JADX_JAR, NODE_DIR } from '../lib/paths.mjs'
import { ensureToolchain, nodeIsNewEnough } from '../lib/toolchain.mjs'

const check = process.argv.includes('--check')
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const say = (...a) => console.log(...a)
let problems = 0
const ok = (msg) => say(`  ok       ${msg}`)
const todo = (msg) => { problems++; say(`  missing  ${msg}`) }

say(`droid-dna setup${check ? ' (check only)' : ''}`)

// Move data from the pre-rename location so the sample catalog is kept.
const legacy = join(homedir(), '.readroid')
if (!process.env.DROID_DNA_HOME && existsSync(legacy) && !existsSync(HOME)) {
  if (check) todo(`${legacy} should move to ${HOME}`)
  else { renameSync(legacy, HOME); ok(`moved ${legacy} to ${HOME}`) }
}

if (!check) mkdirSync(HOME, { recursive: true })

if (existsSync(ENV_FILE)) ok(`${ENV_FILE}`)
else if (check) say(`  note     ${ENV_FILE} not created yet (only needed for MalwareBazaar downloads)`)
else {
  copyFileSync(join(root, '.env.example'), ENV_FILE)
  try { chmodSync(ENV_FILE, 0o600) } catch {}
  ok(`created ${ENV_FILE}; add ABUSECH_API_KEY to fetch known-malware samples`)
}

if (check) {
  nodeIsNewEnough() || existsSync(NODE_DIR) ? ok('Node for REA') : todo('Node 22.19+ for REA (fetched on setup)')
  existsSync(JDK_DIR) ? ok('JDK 21') : todo('JDK 21 (fetched on setup)')
  existsSync(JADX_JAR) ? ok('JADX bridge jar') : todo('JADX bridge jar (fetched on setup)')
} else {
  await ensureToolchain()
  ok('toolchain (Node, JDK 21, JADX bridge jar)')
}

// A user-level `rea` server would shadow the project's and lacks the JADX jar.
try {
  const cfg = JSON.parse(readFileSync(join(homedir(), '.claude.json'), 'utf8'))
  if (cfg.mcpServers?.rea) say('  warning  a user-level `rea` MCP server exists; remove it with `claude mcp remove rea -s user` so the project one is used')
} catch {}

say(problems ? `\n${problems} item(s) outstanding. Run: npm run setup` : '\nDone. Run `npm run claude` in this folder (Claude Code plus the droid-dna pane), approve the project MCP servers, then /scan <sha256|path>.')
process.exit(check && problems ? 1 : 0)

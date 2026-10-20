#!/usr/bin/env node
// One-time setup: provisions the toolchain and the config dir.
// Usage: node droid-dna/bin/setup.mjs [--check]
import { spawnSync } from 'node:child_process'
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

// The pane is a Claude Code plugin served from this repo's own marketplace, enabled at project scope
// (.claude/settings.json) so plain `claude` in this folder has /droid-dna with no flags.
const claude = (...args) => spawnSync('claude', args, { cwd: root, encoding: 'utf8' })
const PLUGIN = 'droid-dna-ui', MARKET = 'droid-dna'
const hasClaude = claude('--version').status === 0
if (!hasClaude) {
  todo('Claude Code (install it, then run setup again): https://docs.claude.com/en/docs/claude-code')
} else {
  let installed = false
  try { installed = JSON.parse(claude('plugin', 'list', '--json').stdout).some(p => p.id === `${PLUGIN}@${MARKET}` && p.scope === 'project') } catch {}
  if (installed) ok(`Claude Code plugin ${PLUGIN} (project scope)`)
  else if (check) todo(`Claude Code plugin ${PLUGIN} (installed on setup)`)
  else {
    // A marketplace already registered for this folder under another name (the pre-rename `readroid`)
    // would swallow the add and then not contain the plugin, so drop it first.
    try {
      for (const m of JSON.parse(claude('plugin', 'marketplace', 'list', '--json').stdout))
        if (m.path === root && m.name !== MARKET) {
          claude('plugin', 'marketplace', 'remove', m.name)
          ok(`removed stale marketplace ${m.name} for this folder`)
        }
    } catch {}
    const steps = [
      ['plugin', 'marketplace', 'add', root, '--scope', 'project'],
      ['plugin', 'install', `${PLUGIN}@${MARKET}`, '--scope', 'project'],
    ]
    for (const step of steps) {
      const r = claude(...step)
      if (r.status !== 0) {
        todo(`Claude Code plugin ${PLUGIN}: \`claude ${step.join(' ')}\` failed: ${(r.stderr || r.stdout).trim().split('\n')[0]}`)
        break
      }
    }
    if (!problems) ok(`Claude Code plugin ${PLUGIN} (project scope)`)
  }
}

say(problems ? `\n${problems} item(s) outstanding. Run: npm run setup` : '\nDone. Run `claude` in this folder, approve the project MCP servers and plugin, then /droid-dna or /scan <sha256|path>.')
process.exit(check && problems ? 1 : 0)

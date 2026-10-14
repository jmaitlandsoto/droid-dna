import { readFileSync } from 'node:fs'
import { ENV_FILE } from './paths.mjs'

// Secrets live in ~/.readroid/.env, outside any repo. A real environment variable wins.
export function loadEnvFile(file = ENV_FILE) {
  let text
  try { text = readFileSync(file, 'utf8') } catch { return }
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/)
    if (!m || line.trimStart().startsWith('#')) continue
    const v = m[2].replace(/^(['"])(.*)\1$/, '$2')
    if (process.env[m[1]] === undefined) process.env[m[1]] = v
  }
}

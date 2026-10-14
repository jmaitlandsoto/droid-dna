// JSON catalog. Only the MCP server writes; writes are atomic (temp file + rename).
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { CATALOG, SCANS } from './paths.mjs'

export function loadCatalog() {
  try { return JSON.parse(readFileSync(CATALOG, 'utf8')) } catch { return { schema: 1, apks: {} } }
}

function atomicWrite(file, text) {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
  const tmp = `${file}.${process.pid}.tmp`
  writeFileSync(tmp, text, { mode: 0o600 })
  renameSync(tmp, file)
}

export function saveCatalog(c) { atomicWrite(CATALOG, JSON.stringify(c, null, 1)) }

// Labels are ground truth from sources or manual review. Scans never write them.
export function upsertApk(c, sha256, patch, source, label) {
  const e = (c.apks[sha256] ??= { sources: [], labels: [] })
  Object.assign(e, Object.fromEntries(Object.entries(patch).filter(([, v]) => v != null)))
  if (source && !e.sources.some(s => s.source === source.source && s.ref === source.ref)) e.sources.push(source)
  if (label && !e.labels.some(l => l.origin === label.origin && l.label === label.label)) e.labels.push(label)
  return e
}

export function writeScan(scan) {
  atomicWrite(join(SCANS, `${scan.sha256}.${scan.id}.json`), JSON.stringify(scan, null, 1))
}

export function listScans(sha256) {
  if (!existsSync(SCANS)) return []
  return readdirSync(SCANS).filter(f => f.endsWith('.json') && (!sha256 || f.startsWith(sha256)))
    .map(f => JSON.parse(readFileSync(join(SCANS, f), 'utf8')))
    .sort((a, b) => (a.startedAt < b.startedAt ? 1 : -1))
}

export const nextScanId = sha256 => listScans(sha256).length + 1

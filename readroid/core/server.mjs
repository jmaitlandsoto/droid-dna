#!/usr/bin/env node
// READroid core: an MCP stdio server with no dependencies. Owns the catalog,
// sample fetching and the cheap analysis tiers. stdout is the protocol; log to stderr.
import { createHash } from 'node:crypto'
import { createReadStream, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync, statSync, chmodSync } from 'node:fs'
import { pipeline } from 'node:stream/promises'
import { tmpdir } from 'node:os'
import { join, resolve, basename } from 'node:path'
import { createInterface } from 'node:readline'
import { loadEnvFile } from '../lib/env.mjs'
import { SAMPLES, REPORTS } from '../lib/paths.mjs'
import { readAesZip } from '../lib/aeszip.mjs'
import { loadCatalog, saveCatalog, upsertApk, writeScan, listScans, nextScanId } from '../lib/catalog.mjs'
import { reaInspectPackage, tier1 } from '../lib/triage.mjs'

loadEnvFile()
const SHA = /^[0-9a-f]{64}$/
const VERDICTS = ['malicious', 'proxyware', 'pup', 'no_indicators', 'inconclusive']

async function sha256File(file) {
  const h = createHash('sha256')
  await pipeline(createReadStream(file), h)
  return h.digest('hex')
}

const text = (obj, isError = false) => ({
  content: [{ type: 'text', text: typeof obj === 'string' ? obj : JSON.stringify(obj, null, 1) }],
  ...(isError ? { isError: true } : {}),
})

function entryOrThrow(c, sha) {
  if (!SHA.test(sha ?? '')) throw new Error('sha256 must be 64 lowercase hex characters')
  const e = c.apks[sha]
  if (!e) throw new Error('Unknown sha256; import or fetch the sample first')
  return e
}

async function mbApi(form) {
  const key = process.env.ABUSECH_API_KEY
  if (!key) throw new Error('ABUSECH_API_KEY is not set. Put it in ~/.readroid/.env')
  const res = await fetch('https://mb-api.abuse.ch/api/v1/', {
    method: 'POST', headers: { 'Auth-Key': key }, body: new URLSearchParams(form),
  })
  return res
}

// Gives analysis a bare APK path, deleted afterwards. Samples stay encrypted at rest.
async function withApk(sha, e, fn) {
  if (!e.localPath || !existsSync(e.localPath)) throw new Error('Sample not on disk; run sample_fetch or sample_import')
  if (!e.localPath.endsWith('.zip')) return fn(e.localPath)
  const dir = mkdtempSync(join(tmpdir(), 'readroid-'))
  try {
    const { data } = readAesZip(readFileSync(e.localPath), 'infected')
    if (createHash('sha256').update(data).digest('hex') !== sha) throw new Error('Extracted sample does not match its SHA-256')
    const p = join(dir, `${sha}.apk`)
    writeFileSync(p, data, { mode: 0o600 })
    return await fn(p)
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

const opened = new Map() // sha256 -> temp dir

function closeAll() { for (const d of opened.values()) rmSync(d, { recursive: true, force: true }); opened.clear() }
process.on('exit', closeAll)
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => process.exit(0))

const TOOLS = {
  catalog_search: {
    description: 'Search the local sample catalog by package name or sha256 prefix, optionally by label.',
    inputSchema: { type: 'object', properties: { query: { type: 'string' }, label: { type: 'string', enum: ['malicious', 'proxyware', 'pup', 'benign'] }, limit: { type: 'integer' } } },
    async run({ query = '', label, limit = 25 }) {
      const q = query.toLowerCase()
      const rows = Object.entries(loadCatalog().apks)
        .filter(([sha, e]) => (!q || sha.startsWith(q) || (e.pkg ?? '').toLowerCase().includes(q) || (e.name ?? '').toLowerCase().includes(q))
          && (!label || e.labels.some(l => l.label === label)))
        .slice(0, limit)
        .map(([sha256, e]) => ({ sha256, pkg: e.pkg, name: e.name, sizeBytes: e.sizeBytes, onDisk: !!e.localPath, labels: e.labels.map(l => `${l.label}${l.family ? ':' + l.family : ''}`), sources: e.sources.map(s => s.source) }))
      return { count: rows.length, results: rows }
    },
  },
  catalog_sync: {
    description: 'Pull sample METADATA (no downloads) from MalwareBazaar into the catalog. Needs ABUSECH_API_KEY.',
    inputSchema: { type: 'object', properties: { tag: { type: 'string', description: 'MalwareBazaar tag, e.g. banker' }, limit: { type: 'integer' } } },
    async run({ tag, limit = 100 }) {
      const form = tag ? { query: 'get_taginfo', tag, limit: String(limit) } : { query: 'get_file_type', file_type: 'apk', limit: String(limit) }
      const body = await (await mbApi(form)).json()
      if (body.query_status !== 'ok') throw new Error(`MalwareBazaar: ${body.query_status}`)
      const c = loadCatalog()
      let added = 0
      for (const r of body.data) {
        if (r.file_type !== 'apk' && !/\.apk$/i.test(r.file_name ?? '')) continue
        if (!c.apks[r.sha256_hash]) added++
        upsertApk(c, r.sha256_hash, { name: r.file_name, sizeBytes: r.file_size, firstSeen: r.first_seen },
          { source: 'malwarebazaar', ref: r.sha256_hash },
          { label: 'malicious', family: r.signature ?? r.tags?.[0] ?? null, origin: 'malwarebazaar', confidence: 0.9 })
      }
      saveCatalog(c)
      return { added, total: Object.keys(c.apks).length }
    },
  },
  sample_import: {
    description: 'Add a local APK file to the catalog (hashes it). The file is left where it is.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
    async run({ path }) {
      const p = resolve(path)
      if (!existsSync(p) || !statSync(p).isFile()) throw new Error('No such file')
      const sha = await sha256File(p)
      const c = loadCatalog()
      upsertApk(c, sha, { localPath: p, sizeBytes: statSync(p).size, name: basename(p) }, { source: 'local', ref: p })
      saveCatalog(c)
      return { sha256: sha, path: p }
    },
  },
  sample_fetch: {
    description: 'Download a catalogued MalwareBazaar sample (kept as an encrypted zip) and verify its SHA-256.',
    inputSchema: { type: 'object', properties: { sha256: { type: 'string' } }, required: ['sha256'] },
    async run({ sha256: sha }) {
      const c = loadCatalog()
      const e = entryOrThrow(c, sha)
      if (e.localPath && existsSync(e.localPath)) return { sha256: sha, alreadyOnDisk: true }
      const res = await mbApi({ query: 'get_file', sha256_hash: sha })
      const buf = Buffer.from(await res.arrayBuffer())
      if (buf[0] !== 0x50 || buf[1] !== 0x4b) throw new Error('MalwareBazaar did not return a zip: ' + buf.toString('utf8', 0, 120))
      const { data } = readAesZip(buf, 'infected')
      if (createHash('sha256').update(data).digest('hex') !== sha) throw new Error('Downloaded sample does not match its SHA-256')
      mkdirSync(SAMPLES, { recursive: true, mode: 0o700 })
      const zipPath = join(SAMPLES, `${sha}.zip`)
      writeFileSync(zipPath, buf, { mode: 0o600 })
      e.localPath = zipPath
      saveCatalog(c)
      return { sha256: sha, storedAs: zipPath, verified: true }
    },
  },
  sample_open: {
    description: 'Extract a catalogued sample to a bare .apk path that REA tools can read. Call sample_close when analysis is finished.',
    inputSchema: { type: 'object', properties: { sha256: { type: 'string' } }, required: ['sha256'] },
    async run({ sha256: sha }) {
      const e = entryOrThrow(loadCatalog(), sha)
      if (!e.localPath || !existsSync(e.localPath)) throw new Error('Sample not on disk; run sample_fetch or sample_import')
      if (!e.localPath.endsWith('.zip')) return { sha256: sha, apkPath: e.localPath, temporary: false }
      if (opened.has(sha)) return { sha256: sha, apkPath: join(opened.get(sha), `${sha}.apk`), temporary: true }
      const dir = mkdtempSync(join(tmpdir(), 'readroid-'))
      try {
        const { data } = readAesZip(readFileSync(e.localPath), 'infected')
        if (createHash('sha256').update(data).digest('hex') !== sha) throw new Error('Extracted sample does not match its SHA-256')
        writeFileSync(join(dir, `${sha}.apk`), data, { mode: 0o600 })
      } catch (err) { rmSync(dir, { recursive: true, force: true }); throw err }
      opened.set(sha, dir)
      return { sha256: sha, apkPath: join(dir, `${sha}.apk`), temporary: true }
    },
  },
  sample_close: {
    description: 'Delete the temporary APK created by sample_open.',
    inputSchema: { type: 'object', properties: { sha256: { type: 'string' } }, required: ['sha256'] },
    async run({ sha256: sha }) {
      const dir = opened.get(sha)
      if (dir) rmSync(dir, { recursive: true, force: true })
      opened.delete(sha)
      return { sha256: sha, deleted: !!dir }
    },
  },
  scan_triage: {
    description: 'Run tier 0 (identity) and tier 1 (static rules via REA) on a catalogued sample. Returns a summary and whether to escalate to the apk-analyst. Full report is written to disk.',
    inputSchema: { type: 'object', properties: { sha256: { type: 'string' } }, required: ['sha256'] },
    async run({ sha256: sha }) {
      const c = loadCatalog()
      const e = entryOrThrow(c, sha)
      const scan = { id: nextScanId(sha), sha256: sha, stage: 'triage', startedAt: new Date().toISOString(), pipelineVersion: '0.1.0', model: null }
      writeScan(scan)
      try {
        const result = await withApk(sha, e, p => reaInspectPackage(p))
        const t1 = tier1(result)
        mkdirSync(REPORTS, { recursive: true, mode: 0o700 })
        const reportPath = join(REPORTS, `${sha}.${scan.id}.json`)
        writeFileSync(reportPath, JSON.stringify({ tier1: t1, rea: result.normalized_result }, null, 1), { mode: 0o600 })
        upsertApk(c, sha, { pkg: t1.package, versionName: t1.versionName })
        saveCatalog(c)
        Object.assign(scan, { reportPath, score: t1.score, escalate: t1.escalate, findings: t1.findings })
        if (t1.escalate) scan.stage = 'triaged'
        else Object.assign(scan, { stage: 'done', verdict: 'no_indicators', confidence: 0.5, finishedAt: new Date().toISOString(), summary: 'Static rules found nothing above the threshold. This is not a statement that the app is safe.', unknowns: ['Tier 1 static rules only; no code was reviewed.'] })
        writeScan(scan)
        return { scanId: scan.id, stage: scan.stage, package: t1.package, versionName: t1.versionName, score: t1.score, threshold: t1.threshold, escalate: t1.escalate, findings: t1.findings, reportPath }
      } catch (err) {
        Object.assign(scan, { stage: 'error', error: String(err.message ?? err), finishedAt: new Date().toISOString() })
        writeScan(scan)
        throw err
      }
    },
  },
  scan_report: {
    description: 'Submit the final structured verdict for the latest scan of a sample. Free-text verdicts are rejected. Use verdict "inconclusive" when you could not examine the code; never "no_indicators" for an app you could not open.',
    inputSchema: {
      type: 'object', required: ['sha256', 'verdict', 'confidence', 'summary', 'findings'],
      properties: {
        sha256: { type: 'string' }, verdict: { type: 'string', enum: VERDICTS },
        confidence: { type: 'number', minimum: 0, maximum: 1 },
        categories: { type: 'array', items: { type: 'string' } },
        summary: { type: 'string' },
        findings: { type: 'array', items: { type: 'object', required: ['rule_id', 'confirmed', 'severity', 'title', 'evidence'], properties: {
          rule_id: { type: 'string' }, confirmed: { type: 'boolean' }, severity: { type: 'string', enum: ['low', 'medium', 'high'] }, title: { type: 'string' },
          evidence: { type: 'array', items: { type: 'object' } } } } },
        endpoints: { type: 'array', items: { type: 'object' } },
        unknowns: { type: 'array', items: { type: 'string' } },
      },
    },
    async run(a) {
      const c = loadCatalog()
      entryOrThrow(c, a.sha256)
      if (!VERDICTS.includes(a.verdict)) throw new Error(`verdict must be one of ${VERDICTS.join(', ')}`)
      if (typeof a.confidence !== 'number' || a.confidence < 0 || a.confidence > 1) throw new Error('confidence must be a number from 0 to 1')
      if (typeof a.summary !== 'string' || !a.summary.trim()) throw new Error('summary is required')
      if (!Array.isArray(a.findings)) throw new Error('findings must be an array')
      for (const f of a.findings) {
        if (!f || typeof f.rule_id !== 'string' || typeof f.confirmed !== 'boolean' || !['low', 'medium', 'high'].includes(f.severity) || typeof f.title !== 'string' || !Array.isArray(f.evidence))
          throw new Error('each finding needs rule_id, confirmed, severity, title and an evidence array')
        if (f.confirmed && f.evidence.length === 0) throw new Error(`finding ${f.rule_id} is marked confirmed but has no evidence`)
      }
      if (a.verdict === 'no_indicators' && !(a.unknowns ?? []).length && a.findings.length === 0 && a.confidence > 0.9)
        throw new Error('A "no_indicators" verdict with confidence above 0.9 must list what was not examined in unknowns')
      const scan = listScans(a.sha256)[0]
      if (!scan) throw new Error('No scan for this sample; run scan_triage first')
      Object.assign(scan, {
        stage: 'done', verdict: a.verdict, confidence: a.confidence, categories: a.categories ?? [], summary: a.summary,
        findings: a.findings, endpoints: a.endpoints ?? [], unknowns: a.unknowns ?? [], finishedAt: new Date().toISOString(), verdictBy: 'analyst',
      })
      writeScan(scan)
      return { recorded: true, scanId: scan.id, verdict: a.verdict }
    },
  },
  scan_list: {
    description: 'List scans (newest first), optionally for one sample.',
    inputSchema: { type: 'object', properties: { sha256: { type: 'string' } } },
    async run({ sha256: sha }) {
      return listScans(sha).slice(0, 50).map(({ findings, ...s }) => ({ ...s, findingCount: findings?.length ?? 0 }))
    },
  },
}

// ---- minimal MCP over stdio (newline-delimited JSON-RPC) ----
const send = m => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...m }) + '\n')

async function handle(msg) {
  const { id, method, params } = msg
  if (id === undefined) return // notification
  try {
    if (method === 'initialize')
      return send({ id, result: { protocolVersion: params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'readroid-core', version: '0.1.0' } } })
    if (method === 'ping') return send({ id, result: {} })
    if (method === 'tools/list')
      return send({ id, result: { tools: Object.entries(TOOLS).map(([name, t]) => ({ name, description: t.description, inputSchema: t.inputSchema })) } })
    if (method === 'tools/call') {
      const tool = TOOLS[params?.name]
      if (!tool) return send({ id, error: { code: -32602, message: `Unknown tool ${params?.name}` } })
      try { return send({ id, result: text(await tool.run(params.arguments ?? {})) }) }
      catch (e) { return send({ id, result: text(String(e.message ?? e), true) }) }
    }
    send({ id, error: { code: -32601, message: `Method not found: ${method}` } })
  } catch (e) { send({ id, error: { code: -32603, message: String(e.message ?? e) } }) }
}

createInterface({ input: process.stdin }).on('line', line => {
  if (!line.trim()) return
  let msg
  try { msg = JSON.parse(line) } catch { return }
  handle(msg)
})

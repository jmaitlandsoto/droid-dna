#!/usr/bin/env node
// droid-dna core: an MCP stdio server with no dependencies. Owns the catalog,
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
import { inspectApk } from '../lib/native.mjs'
import { diffScans } from '../lib/diff.mjs'
import { baseline, uniqueIds, checkResolution, openItems, capConfidence, summarize, BLOCKERS, MAX_ROUND, MAX_ITEMS, norm, leadSkipReason, overlapsBaseline } from '../lib/ledger.mjs'

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
  if (!key) throw new Error('ABUSECH_API_KEY is not set. Put it in ~/.droid-dna/.env')
  const res = await fetch('https://mb-api.abuse.ch/api/v1/', {
    method: 'POST', headers: { 'Auth-Key': key }, body: new URLSearchParams(form),
  })
  return res
}

// Gives analysis a bare APK path, deleted afterwards. Samples stay encrypted at rest.
async function withApk(sha, e, fn) {
  if (!e.localPath || !existsSync(e.localPath)) throw new Error('Sample not on disk; run sample_fetch or sample_import')
  if (!e.localPath.endsWith('.zip')) return fn(e.localPath)
  const dir = mkdtempSync(join(tmpdir(), 'droid-dna-'))
  try {
    const { data } = readAesZip(readFileSync(e.localPath), 'infected')
    if (createHash('sha256').update(data).digest('hex') !== sha) throw new Error('Extracted sample does not match its SHA-256')
    const p = join(dir, `${sha}.apk`)
    writeFileSync(p, data, { mode: 0o600 })
    return await fn(p)
  } finally { rmSync(dir, { recursive: true, force: true }) }
}


function latestScan(sha) {
  entryOrThrow(loadCatalog(), sha)
  const scan = listScans(sha)[0]
  if (!scan) throw new Error('No scan for this sample; run scan_triage first')
  if (scan.ledger && uniqueIds(scan.ledger.items)) writeScan(scan)
  return scan
}

// Compact by default: a full ledger runs to 100 KB, which agents cannot read. Evidence comes one item at a time.
function ledgerView(scan, full = false) {
  const { items, dropped } = scan.ledger
  const row = i => (full ? i : { id: i.id, kind: i.kind, round: i.round, parent: i.parent, title: i.title, status: i.status, blocker: i.blocker, mergedInto: i.mergedInto, answer: i.answer?.slice(0, 280), evidenceCount: i.evidence?.length })
  return { scanId: scan.id, ...summarize(scan.ledger), maxRound: MAX_ROUND, openIds: openItems(scan.ledger).map(i => i.id), items: items.map(row), dropped }
}

const opened = new Map() // sha256 -> temp dir

function closeAll() { for (const d of opened.values()) rmSync(d, { recursive: true, force: true }); opened.clear() }
process.on('exit', closeAll)
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => process.exit(0))

const TOOLS = {
  catalog_search: {
    description: 'Search the local sample catalog by package name or sha256 prefix, optionally by label.',
    inputSchema: { type: 'object', properties: { query: { type: 'string' }, label: { type: 'string', enum: ['malicious', 'proxyware', 'pup', 'benign'] }, artifact: { type: 'string', description: 'sha256 (or prefix) of a native lib or embedded file; finds samples that ship it' }, limit: { type: 'integer' } } },
    async run({ query = '', label, artifact, limit = 25 }) {
      const q = query.toLowerCase()
      const rows = Object.entries(loadCatalog().apks)
        .filter(([sha, e]) => (!q || sha.startsWith(q) || (e.pkg ?? '').toLowerCase().includes(q) || (e.name ?? '').toLowerCase().includes(q))
          && (!label || e.labels.some(l => l.label === label))
          && (!artifact || (e.artifactHashes ?? []).some(h => h.startsWith(artifact.toLowerCase()))))
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
      const dir = mkdtempSync(join(tmpdir(), 'droid-dna-'))
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
  sample_inspect_native: {
    description: 'Metadata only, nothing is extracted or run: hashes, kinds and ELF packing signals for the native libraries (lib/), raw resources, assets and extra dex files inside a sample. Use it to see what payloads ship with the app and whether they are packed. Records hashes so catalog_search can find samples sharing a payload.',
    inputSchema: { type: 'object', properties: { sha256: { type: 'string' } }, required: ['sha256'] },
    async run({ sha256: sha }) {
      const native = await withApk(sha, entryOrThrow(loadCatalog(), sha), async p => inspectApk(readFileSync(p)))
      const c = loadCatalog() // reload: another call may have written the catalog while we worked
      upsertApk(c, sha, { artifactHashes: native.artifactHashes })
      saveCatalog(c)
      const { artifactHashes, ...out } = native
      return out
    },
  },
  scan_triage: {
    description: 'Run tier 0 (identity) and tier 1 (static rules via REA) on a catalogued sample. Returns a summary and whether to escalate to deep analysis (the investigation ledger). Full report is written to disk.',
    inputSchema: { type: 'object', properties: { sha256: { type: 'string' } }, required: ['sha256'] },
    async run({ sha256: sha }) {
      const c = loadCatalog()
      const e = entryOrThrow(c, sha)
      const scan = { id: nextScanId(sha), sha256: sha, stage: 'triage', startedAt: new Date().toISOString(), pipelineVersion: '0.1.0', model: null }
      writeScan(scan)
      try {
        const { result, native } = await withApk(sha, e, async p => ({ result: await reaInspectPackage(p), native: inspectApk(readFileSync(p)) }))
        const t1 = tier1(result, native)
        mkdirSync(REPORTS, { recursive: true, mode: 0o700 })
        const reportPath = join(REPORTS, `${sha}.${scan.id}.json`)
        writeFileSync(reportPath, JSON.stringify({ tier1: t1, native, rea: result.normalized_result }, null, 1), { mode: 0o600 })
        const fresh = loadCatalog() // reload: another call may have written the catalog while we worked
        upsertApk(fresh, sha, { pkg: t1.package, versionName: t1.versionName, artifactHashes: native.artifactHashes })
        saveCatalog(fresh)
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
  ledger_init: {
    description: 'Build the investigation checklist for the latest scan of a sample from the stored tier 1 report. Safe to call again: an existing ledger is returned unchanged. The checklist must be closed before scan_report accepts a verdict.',
    inputSchema: { type: 'object', properties: { sha256: { type: 'string' } }, required: ['sha256'] },
    async run({ sha256: sha }) {
      const scan = latestScan(sha)
      if (!scan.ledger) {
        if (!scan.reportPath || !existsSync(scan.reportPath)) throw new Error('The scan has no tier 1 report; run scan_triage first')
        scan.ledger = { createdAt: new Date().toISOString(), items: baseline(JSON.parse(readFileSync(scan.reportPath, 'utf8'))), dropped: [] }
        writeScan(scan)
      }
      return ledgerView(scan)
    },
  },
  ledger_get: {
    description: 'Read the investigation checklist of the latest scan. Without id: a compact table of every item (status, blocker, the start of the answer). With id: that one item in full, with its evidence. full:true returns everything (very large).',
    inputSchema: { type: 'object', properties: { sha256: { type: 'string' }, id: { type: 'string' }, full: { type: 'boolean' } }, required: ['sha256'] },
    async run({ sha256: sha, id, full }) {
      const scan = latestScan(sha)
      if (!scan.ledger) throw new Error('No ledger yet; call ledger_init')
      if (id) return scan.ledger.items.find(i => i.id === id) ?? (() => { throw new Error('Unknown item id') })()
      return ledgerView(scan, !!full)
    },
  },
  ledger_add: {
    description: 'Planner only, before any item is resolved: add sample-specific items to the checklist. Each needs a title and a concrete question that names where to start.',
    inputSchema: { type: 'object', required: ['sha256', 'items'], properties: { sha256: { type: 'string' }, items: { type: 'array', items: { type: 'object', required: ['title', 'question'], properties: { title: { type: 'string' }, question: { type: 'string' } } } } } },
    async run({ sha256: sha, items }) {
      const scan = latestScan(sha)
      if (!scan.ledger) throw new Error('No ledger yet; call ledger_init')
      if (scan.ledger.items.some(i => i.status !== 'open')) throw new Error('Investigation has started; new questions can only be added as leads when resolving an item')
      if (!Array.isArray(items) || !items.length) throw new Error('items must be a non-empty array')
      const added = [], skipped = [], overlaps = []
      for (const it of items) {
        if (typeof it?.title !== 'string' || typeof it?.question !== 'string' || it.question.trim().length < 30) throw new Error('each item needs a title and a question of at least a sentence')
        const n = scan.ledger.items.length
        const same = scan.ledger.items.find(i => norm(i.title) === norm(it.title))
        if (same) { skipped.push({ title: it.title.slice(0, 120), reason: `same title as ${same.id}` }); continue }
        if (n >= MAX_ITEMS) { scan.ledger.dropped.push(`${it.title} (checklist full)`); continue }
        const item = { id: `x-${n + 1}`, kind: 'planned', round: 0, title: it.title.slice(0, 120), question: it.question.slice(0, 1200), status: 'open' }
        for (const o of overlapsBaseline(item, scan.ledger.items)) overlaps.push({ new: item.id, ...o })
        scan.ledger.items.push(item); added.push(item.id)
      }
      writeScan(scan)
      return { added, ...(skipped.length && { skipped }), ...(overlaps.length && { overlaps }), ...summarize(scan.ledger) }
    },
  },
  ledger_resolve: {
    description: `Close one checklist item. The orchestrator may use status merged with mergedInto for a lead that another item already covers. status is confirmed or rejected (needs evidence entries with "where" and "what") or unresolved (needs a blocker: ${Object.keys(BLOCKERS).filter(b => b !== 'round_limit').join(', ')} and a detail). "I did not read it" is not a blocker. Put follow-up questions in leads. Use remaining for what a confirmed or rejected item left unanswered. Leads from an item stopped by a tool limit, and leads that repeat an existing question, are skipped and listed in skippedLeads.`,
    inputSchema: { type: 'object', required: ['sha256', 'id', 'status', 'answer'], properties: {
      sha256: { type: 'string' }, id: { type: 'string' }, status: { type: 'string', enum: ['confirmed', 'rejected', 'unresolved', 'merged'] },
      answer: { type: 'string' }, mergedInto: { type: 'string', description: 'status merged only: id of the item that already covers this one' }, evidence: { type: 'array', items: { type: 'object', properties: { where: { type: 'string' }, what: { type: 'string' } } } },
      blocker: { type: 'string', enum: Object.keys(BLOCKERS) }, detail: { type: 'string' },
      remaining: { type: 'string', description: 'confirmed or rejected only: the part of the question you could not answer. It is listed under unknowns; do not raise a lead for it.' },
      endpoints: { type: 'array', items: { type: 'object' } },
      leads: { type: 'array', items: { type: 'object', required: ['title', 'question'], properties: { title: { type: 'string' }, question: { type: 'string' } } } },
    } },
    async run(a) {
      const scan = latestScan(a.sha256)
      if (!scan.ledger) throw new Error('No ledger yet; call ledger_init')
      if (scan.ledger.items.filter(i => i.id === a.id).length > 1) throw new Error(`Item id ${a.id} is ambiguous`)
      const item = scan.ledger.items.find(i => i.id === a.id)
      const err = checkResolution(item, a, scan.ledger.items)
      if (err) throw new Error(err)
      Object.assign(item, { status: a.status, answer: a.answer.slice(0, 3000), resolvedAt: new Date().toISOString() })
      if (a.status === 'unresolved') Object.assign(item, { blocker: a.blocker, detail: a.detail.slice(0, 500) })
      else if (a.status === 'merged') item.mergedInto = a.mergedInto
      else item.evidence = a.evidence.slice(0, 20)
      if (Array.isArray(a.endpoints) && a.endpoints.length) item.endpoints = a.endpoints.slice(0, 20)
      if (typeof a.remaining === 'string' && a.remaining.trim() && a.status !== 'unresolved' && a.status !== 'merged') item.remaining = a.remaining.slice(0, 500)
      const added = [], skippedLeads = []
      for (const l of Array.isArray(a.leads) ? a.leads : []) {
        const why = leadSkipReason(item, l, scan.ledger.items)
        if (why) { skippedLeads.push({ title: String(l?.title ?? '').slice(0, 120), reason: why }); continue }
        if (item.round + 1 > MAX_ROUND || scan.ledger.items.length >= MAX_ITEMS) { scan.ledger.dropped.push(`${l.title} (from ${item.id}; ${item.round + 1 > MAX_ROUND ? 'round limit' : 'checklist full'})`); continue }
        const lead = { id: `l-${scan.ledger.items.length + 1}`, kind: 'lead', round: item.round + 1, parent: item.id, title: l.title.slice(0, 120), question: l.question.slice(0, 1200), status: 'open' }
        scan.ledger.items.push(lead); added.push(lead.id)
      }
      writeScan(scan)
      return { recorded: item.id, newLeads: added, ...(skippedLeads.length && { skippedLeads }), ...summarize(scan.ledger) }
    },
  },
  ledger_close_out: {
    description: 'Orchestrator only: mark every still-open item unresolved with blocker round_limit, once the round limit is reached. Never use it to skip work that could still be done.',
    inputSchema: { type: 'object', properties: { sha256: { type: 'string' } }, required: ['sha256'] },
    async run({ sha256: sha }) {
      const scan = latestScan(sha)
      if (!scan.ledger) throw new Error('No ledger yet; call ledger_init')
      const open = openItems(scan.ledger)
      if (open.some(i => i.round < MAX_ROUND)) throw new Error(`Items below round ${MAX_ROUND} are still open (${open.filter(i => i.round < MAX_ROUND).map(i => i.id).join(', ')}); investigate them first`)
      for (const i of open) Object.assign(i, { status: 'unresolved', blocker: 'round_limit', detail: 'Reached the last investigation round before this was started', answer: 'Not investigated: round limit reached', resolvedAt: new Date().toISOString() })
      writeScan(scan)
      return summarize(scan.ledger)
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
        native: { type: 'array', items: { type: 'object' }, description: 'Native payloads examined: path, sha256, packed, what was learned' },
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
      let confidence = a.confidence, capNote
      const unknowns = [...(a.unknowns ?? [])]
      if (scan.escalate) {
        if (!scan.ledger) throw new Error('This scan was escalated, so it needs an investigation ledger. Call ledger_init, then investigate every item.')
        const open = openItems(scan.ledger)
        if (open.length) throw new Error(`${open.length} checklist items are still open: ${open.map(i => `${i.id} (${i.title})`).join('; ')}. Investigate or close each one before submitting a verdict.`)
        const cap = capConfidence(a.verdict, a.confidence, scan.ledger, a.findings.filter(f => f.confirmed).length)
        confidence = cap.confidence
        if (cap.capped) capNote = `confidence lowered from ${a.confidence} to ${confidence}: ${cap.reasons.join('; ')}`
        for (const i of scan.ledger.items.filter(x => x.status === 'unresolved')) unknowns.push(`${i.title}: ${i.blocker} - ${i.detail}`)
        for (const i of scan.ledger.items.filter(x => x.remaining)) unknowns.push(`${i.title}: not answered - ${i.remaining}`)
        for (const d of scan.ledger.dropped) unknowns.push(`Lead not followed: ${d}`)
      }
      Object.assign(scan, {
        stage: 'done', verdict: a.verdict, confidence, ...(capNote && { confidenceRequested: a.confidence, confidenceNote: capNote }), categories: a.categories ?? [], summary: a.summary,
        findings: a.findings, endpoints: a.endpoints ?? [], unknowns, native: a.native ?? [], finishedAt: new Date().toISOString(), verdictBy: 'analyst',
        ...(scan.ledger && { ledgerSummary: summarize(scan.ledger) }),
      })
      const previous = listScans(a.sha256).find(x => x.id !== scan.id && x.stage === 'done')
      if (previous) scan.delta = diffScans(previous, scan)
      writeScan(scan)
      return { recorded: true, scanId: scan.id, ...(scan.delta && { delta: scan.delta }), verdict: a.verdict, confidence, ...(capNote && { note: capNote }) }
    },
  },
  scan_list: {
    description: 'List scans (newest first), optionally for one sample.',
    inputSchema: { type: 'object', properties: { sha256: { type: 'string' } } },
    async run({ sha256: sha }) {
      return listScans(sha).slice(0, 50).map(({ findings, ledger, ...s }) => ({ ...s, findingCount: findings?.length ?? 0, ...(ledger && { ledger: summarize(ledger) }) }))
    },
  },
  scan_get: {
    description: 'Read one scan in full, findings and evidence included (scan_list leaves findings out). Latest scan of the sample unless id is given. The checklist is summarized; use ledger_get for its items.',
    inputSchema: { type: 'object', required: ['sha256'], properties: { sha256: { type: 'string' }, id: { type: 'integer' } } },
    async run({ sha256: sha, id }) {
      entryOrThrow(loadCatalog(), sha)
      const scan = id === undefined ? listScans(sha)[0] : listScans(sha).find(s => s.id === id)
      if (!scan) throw new Error('No such scan; run scan_triage first')
      const { ledger, ...rest } = scan
      return { ...rest, findings: scan.findings ?? [], ...(ledger && { ledger: summarize(ledger) }) }
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
      return send({ id, result: { protocolVersion: params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'droid-dna-core', version: '0.1.0' } } })
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

// The investigation ledger: a checklist the code builds and the agents must close.
// The server, not a model, decides what must be looked at and when the work is done.
export const BLOCKERS = {
  packed_native: 'native code is packed or has no readable strings or imports',
  encrypted_payload: 'a payload is encrypted and the key or routine cannot be read from the sample',
  needs_execution: 'answering needs running the sample, which READroid never does',
  tool_error: 'the analysis tools failed on this item (say how)',
  not_in_sample: 'the thing asked about is not present in the sample (say what you searched)',
  round_limit: 'the investigation round limit was reached before this was started',
}
export const MAX_ROUND = 3
export const MAX_ITEMS = 60

const slug = s => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40)
const short = sha => sha.slice(0, 8)

// Baseline items from the stored tier 1 report. Models can add to these but never remove them.
export function baseline(report) {
  const items = []
  const add = (id, title, question) => items.push({ id, kind: 'baseline', round: 0, title, question, status: 'open' })
  add('b-manifest', 'Map the manifest',
    'List the launcher activity, services and receivers started at boot or on SMS/network events, exported components, and any accessibility, notification-listener or device-admin declaration. Note every component named in the manifest that has no class in the dex.')
  add('b-entry', 'What runs at start and at boot',
    'Read the Application class and each boot or start entry point and follow the calls down to the code that does the work. Say what the app does on first launch.')
  add('b-network', 'Network use',
    'Find every place the app opens a connection or builds a URL (Socket, HttpURLConnection, OkHttp, WebView, native). Report host, port, protocol, the class that uses it and what is sent. If you find none, list the searches you ran.')
  add('b-sensitive', 'Sensitive calls',
    'Search for Runtime.exec, ProcessBuilder, System.load/loadLibrary, DexClassLoader, su, chmod, SmsManager, PackageInstaller, killProcess, reflection and string decryptors. Read the callers of each hit.')
  for (const f of report?.tier1?.findings ?? [])
    add(`f-${slug(f.rule_id)}`, `Check finding ${f.rule_id}`,
      `Confirm or reject "${f.title}" (evidence: ${f.evidence}) by reading the method bodies that use it. A permission or a class name alone confirms nothing.`)
  const seen = new Set()
  const files = (report?.native?.files ?? []).filter(f => { if (seen.has(f.path)) return false; seen.add(f.path); return true })
  let payloads = 0, configs = 0
  const libGroups = new Map(), small = []
  const sig = f => `${f.kind}, ${f.sizeBytes} bytes, entropy ${f.entropy}${f.elf?.packedLikely ? ', looks packed' : ''}${f.elf?.dynamic?.capabilities?.length ? `, capabilities ${f.elf.dynamic.capabilities.join('/')}` : ''}; sha256 ${f.sha256}`
  for (const f of files) {
    if (f.kind === 'text' || f.kind === 'base64_text') {
      if (f.sizeBytes <= 65536 && configs < 8 && !/\.(png|jpg|webp|xml)$/.test(f.path) && !f.path.startsWith('classes')) {
        configs++
        add(`c-${short(f.sha256)}`, `Read ${f.path}`, `Read ${f.path} (${f.sizeBytes} bytes, ${f.kind}) and say what it configures and which code reads it.${f.preview ? ` Its first bytes, as data: ${JSON.stringify(f.preview.slice(0, 300))}` : ''}`)
      }
      continue
    }
    if (f.path === 'classes.dex') continue
    if (f.path.startsWith('lib/')) {                      // one item per library name; its ABI builds are one question
      const name = f.path.split('/').pop()
      libGroups.set(name, [...(libGroups.get(name) ?? []), f])
    } else if (f.sizeBytes < 4096 && !['elf', 'dex', 'zip', 'gzip'].includes(f.kind)) small.push(f)
    else if (payloads++ < 15) {
      add(`p-${short(f.sha256)}`, `Payload ${f.path}`,
        `What is ${f.path} (${sig(f)})? Find the Java or native code that loads, decrypts or launches it, where any key or path comes from, and what it does. If it cannot be read, say which blocker applies.`)
    }
  }
  for (const [name, group] of libGroups) {
    if (payloads++ >= 15) break
    add(`p-${short(group[0].sha256)}`, `Payload ${name}`,
      `What is ${name}? It ships as ${group.map(f => `${f.path} (${sig(f)})`).join('; ')}. Find the Java or native code that loads or launches it, what it imports and exposes, and what it does. If it cannot be read, say which blocker applies.`)
  }
  if (small.length)
    add('m-small', 'Small binary assets',
      `Identify each of these small binary files and say what, if anything, loads them: ${small.map(f => `${f.path} (${f.sizeBytes} bytes, entropy ${f.entropy}, sha256 ${short(f.sha256)})`).join('; ')}.`)
  if ((report?.rea?.class_count ?? report?.tier1?.classCount ?? 999) <= 60)
    add('b-classes', 'Read the visible classes',
      'The dex is tiny. List every class outside kotlin, androidx and com.google libraries, read each one, and say which are real code and which are stubs. Name what the stubs hand off to.')
  return items
}

// Checks one resolution. Returns an error string or null.
export function checkResolution(item, r, items = []) {
  if (!item) return 'Unknown item id'
  if (item.status !== 'open') return `Item ${item.id} is already ${item.status}`
  if (!['confirmed', 'rejected', 'unresolved', 'merged'].includes(r.status)) return 'status must be confirmed, rejected, unresolved or merged'
  if (typeof r.answer !== 'string' || r.answer.trim().length < 20) return 'answer must say what you found, in at least a sentence'
  if (r.status === 'merged') {
    const into = items.find(i => i.id === r.mergedInto)
    if (!into || into.id === item.id || into.status === 'merged') return 'merged needs mergedInto: the id of another item that is not itself merged'
    return null
  }
  if (r.status === 'unresolved') {
    if (!BLOCKERS[r.blocker] || r.blocker === 'round_limit') return `unresolved needs a blocker from: ${Object.keys(BLOCKERS).filter(b => b !== 'round_limit').join(', ')}`
    if (typeof r.detail !== 'string' || r.detail.trim().length < 15) return 'unresolved needs a detail naming exactly what stopped you'
    return null
  }
  const ev = r.evidence
  if (!Array.isArray(ev) || !ev.length) return `${r.status} needs evidence`
  if (!ev.every(e => e && typeof e.where === 'string' && e.where && typeof e.what === 'string' && e.what)) return 'each evidence entry needs "where" (class, method or file) and "what" (what the code or data does)'
  return null
}

export function openItems(ledger) { return ledger.items.filter(i => i.status === 'open') }

// Confidence cannot exceed what the ledger supports.
export function capConfidence(verdict, confidence, ledger, confirmedFindings) {
  const unresolved = ledger.items.filter(i => i.status === 'unresolved')
  const hidden = unresolved.some(i => ['packed_native', 'encrypted_payload', 'needs_execution'].includes(i.blocker))
  let cap = 0.95
  const reasons = []
  if (hidden) { cap = Math.min(cap, verdict === 'no_indicators' ? 0.4 : 0.9); reasons.push('a payload could not be read') }
  if (unresolved.length && verdict === 'no_indicators') { cap = Math.min(cap, 0.5); reasons.push('items are unresolved') }
  if (unresolved.some(i => i.blocker === 'tool_error')) { cap = Math.min(cap, 0.7); reasons.push('tools failed on some items') }
  if (['malicious', 'proxyware', 'pup'].includes(verdict) && confirmedFindings === 0) { cap = Math.min(cap, 0.5); reasons.push('no finding is confirmed with evidence') }
  return { confidence: Math.min(confidence, cap), capped: confidence > cap, reasons }
}

export function summarize(ledger) {
  const count = s => ledger.items.filter(i => i.status === s).length
  return { total: ledger.items.length, open: count('open'), confirmed: count('confirmed'), rejected: count('rejected'), unresolved: count('unresolved'), merged: count('merged'), dropped: ledger.dropped?.length ?? 0 }
}

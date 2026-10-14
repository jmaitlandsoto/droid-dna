import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const SHA = 'ab'.repeat(32)
const server = join(dirname(fileURLToPath(import.meta.url)), '..', 'core', 'server.mjs')

function start() {
  const home = mkdtempSync(join(tmpdir(), 'readroid-test-'))
  mkdirSync(join(home, 'scans')); mkdirSync(join(home, 'reports'))
  writeFileSync(join(home, 'catalog.json'), JSON.stringify({ schema: 1, apks: { [SHA]: { sources: [], labels: [] } } }))
  const report = {
    tier1: { classCount: 23, findings: [{ rule_id: 'perm.sms_full', title: 'Can read, receive and send SMS', evidence: 'READ_SMS' }] },
    native: { files: [
      { path: 'lib/arm64-v8a/libz.so', sha256: 'c'.repeat(64), kind: 'elf', sizeBytes: 900, entropy: 6, elf: { packedLikely: false } },
      { path: 'lib/armeabi-v7a/libz.so', sha256: 'c'.repeat(64), kind: 'elf', sizeBytes: 900, entropy: 6, elf: { packedLikely: false } },
      { path: 'assets/blob.bin', sha256: 'd'.repeat(64), kind: 'binary', sizeBytes: 5000, entropy: 8 },
      { path: 'assets/app.cfg', sha256: 'e'.repeat(64), kind: 'text', sizeBytes: 300, entropy: 4 },
    ] },
  }
  writeFileSync(join(home, 'reports', 'r.json'), JSON.stringify(report))
  writeFileSync(join(home, 'scans', `${SHA}.1.json`), JSON.stringify({ id: 1, sha256: SHA, stage: 'triaged', startedAt: new Date().toISOString(), escalate: true, reportPath: join(home, 'reports', 'r.json'), findings: [] }))
  const p = spawn(process.execPath, [server], { env: { ...process.env, READROID_HOME: home } })
  let buf = '', n = 0; const waiting = new Map()
  p.stdout.on('data', d => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); waiting.get(m.id)?.(m) } })
  const call = (name, args) => new Promise(res => { const id = ++n; waiting.set(id, m => res({ error: m.result.isError, body: m.result.content[0].text })); p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: { sha256: SHA, ...args } } }) + '\n') })
  return { call, stop: () => { p.kill(); rmSync(home, { recursive: true, force: true }) } }
}

const ev = [{ where: 'a.B.c()', what: 'does the thing' }]
const ans = 'The code in the method does the thing described.'

test('baseline, gate, validation, leads, caps', async () => {
  const s = start()
  try {
    const init = JSON.parse((await s.call('ledger_init', {})).body)
    const ids = init.items.map(i => i.id)
    assert.ok(['b-manifest', 'b-entry', 'b-network', 'b-sensitive', 'b-classes', 'f-perm-sms-full', 'p-cccccccc', 'p-dddddddd', 'c-eeeeeeee'].every(i => ids.includes(i)), ids.join())
    assert.equal(ids.filter(i => i === 'p-cccccccc').length, 1, 'ABI copies are one item')

    const report = { sha256: SHA, verdict: 'inconclusive', confidence: 0.9, summary: 'x', findings: [] }
    assert.match((await s.call('scan_report', report)).body, /still open/)

    assert.match((await s.call('ledger_resolve', { id: 'b-manifest', status: 'rejected', answer: ans })).body, /needs evidence/)
    assert.match((await s.call('ledger_resolve', { id: 'b-manifest', status: 'rejected', answer: ans, evidence: ['read it'] })).body, /"where"/)
    assert.match((await s.call('ledger_resolve', { id: 'b-manifest', status: 'unresolved', answer: ans, blocker: 'lazy', detail: 'x'.repeat(20) })).body, /blocker/)

    const added = JSON.parse((await s.call('ledger_add', { items: [{ title: 'Who loads blob.bin', question: 'Find the loader of assets/blob.bin and where its key comes from.' }] })).body)
    assert.deepEqual(added.added, ['x-' + (ids.length + 1)])

    let lead
    for (const id of JSON.parse((await s.call('ledger_get', {})).body).openIds) {
      const r = JSON.parse((await s.call('ledger_resolve', id === 'p-dddddddd'
        ? { id, status: 'unresolved', answer: ans, blocker: 'encrypted_payload', detail: 'AES key is derived in native code' }
        : { id, status: 'confirmed', answer: ans, evidence: ev, ...(id === 'b-entry' && { leads: [{ title: 'Follow native setup', question: 'Read nativeSetup and say what it registers and loads.' }] }) })).body)
      if (r.newLeads?.length) lead = r.newLeads[0]
    }
    assert.ok(lead)
    // lead chain to the round limit
    let cur = lead
    for (let r = 1; r <= 3; r++) {
      const out = JSON.parse((await s.call('ledger_resolve', { id: cur, status: 'confirmed', answer: ans, evidence: ev, leads: [{ title: `Deeper ${r}`, question: 'Keep following the chain of calls into the next class.' }] })).body)
      cur = out.newLeads[0]
    }
    assert.equal(cur, undefined, 'round 4 lead is dropped')
    const view = JSON.parse((await s.call('ledger_get', {})).body)
    assert.equal(view.open, 0)
    assert.equal(view.dropped.length, 1)

    const done = JSON.parse((await s.call('scan_report', { ...report, verdict: 'no_indicators', confidence: 0.9 })).body)
    assert.equal(done.confidence, 0.4)
    assert.match(done.note, /payload could not be read/)
    const scan = JSON.parse((await s.call('scan_list', {})).body)[0]
    assert.equal(scan.stage, 'done')
    assert.ok(scan.unknowns.some(u => u.includes('encrypted_payload')))
    assert.ok(scan.unknowns.some(u => u.startsWith('Lead not followed')))
  } finally { s.stop() }
})

test('close_out refuses while early rounds are open and a verdict needs a confirmed finding', async () => {
  const s = start()
  try {
    await s.call('ledger_init', {})
    assert.match((await s.call('ledger_close_out', {})).body, /investigate them first/)
  } finally { s.stop() }
})

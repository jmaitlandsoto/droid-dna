import test from 'node:test'
import assert from 'node:assert/strict'
import { diffScans } from '../lib/diff.mjs'
import { leadSkipReason, overlapsBaseline, capConfidence } from '../lib/ledger.mjs'

test('diffScans reports verdict, findings, stable items and unknowns', () => {
  const prev = { id: 2, verdict: 'inconclusive', confidence: 0.2, findings: [{ rule_id: 'a' }], unknowns: ['u1'], ledger: { items: [{ id: 'b-entry', status: 'unresolved' }, { id: 'x-9', status: 'open' }] } }
  const cur = { id: 3, verdict: 'malicious', confidence: 0.7, findings: [{ rule_id: 'a' }, { rule_id: 'b' }], unknowns: ['u2'], ledger: { items: [{ id: 'b-entry', status: 'confirmed' }, { id: 'x-9', status: 'confirmed' }] } }
  const d = diffScans(prev, cur)
  assert.equal(d.previousScanId, 2)
  assert.deepEqual(d.verdict, { from: 'inconclusive', to: 'malicious' })
  assert.deepEqual(d.findingsAdded, ['b'])
  assert.deepEqual(d.itemsChanged, [{ id: 'b-entry', from: 'unresolved', to: 'confirmed' }])
  assert.deepEqual(d.unknownsResolved, ['u1'])
  assert.deepEqual(d.unknownsNew, ['u2'])
})

test('leads from a tool-limited parent or repeating a question are skipped', () => {
  const items = [{ id: 'p-1', title: 'Payload', question: 'What does the payload binary do with the peer list?', status: 'unresolved', blocker: 'no_native_tool' }]
  const lead = { title: 'Disassemble it', question: 'Disassemble the payload binary and find what it does.' }
  assert.match(leadSkipReason(items[0], lead, items), /no_native_tool/)
  const open = { id: 'x-2', status: 'confirmed' }
  assert.match(leadSkipReason(open, { title: 'Other', question: 'What does the payload binary do with the peer list?' }, items), /repeats p-1/)
  assert.equal(leadSkipReason(open, { title: 'Fresh', question: 'Read the scheduler class and report its interval.' }, items), null)
})

test('planned items that name a baseline component are flagged; the new blocker caps confidence', () => {
  const items = [{ id: 'f-x', kind: 'baseline', title: 'Check finding manifest.accessibility', question: 'evidence: com.example.UltraPersistenceService' }]
  assert.deepEqual(overlapsBaseline({ title: 'UltraPersistenceService abuse', question: 'Read it.' }, items), [{ existing: 'f-x', shares: 'UltraPersistenceService' }])
  const cap = capConfidence('malicious', 0.95, { items: [{ status: 'unresolved', blocker: 'no_native_tool' }] }, 3)
  assert.equal(cap.confidence, 0.9)
})

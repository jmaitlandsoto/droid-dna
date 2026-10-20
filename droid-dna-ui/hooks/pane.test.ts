import { test, expect } from 'claude-code/testing'

const ok = (obj: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(obj) }] })

const SHA = 'a'.repeat(64)
const calls: string[] = []

const scan = { id: 1, sha256: SHA, stage: 'done', startedAt: '2026-10-19T10:00:00Z', verdict: 'malicious', confidence: 0.8, findingCount: 1 }

const answers: Record<string, unknown> = {
  catalog_search: { count: 1, results: [{ sha256: SHA, pkg: 'io.example.app', sizeBytes: 100, onDisk: false, labels: ['malicious:Test'], sources: ['malwarebazaar'] }] },
  scan_list: [scan],
  scan_get: { ...scan, summary: 'steals SMS', findings: [{ rule_id: 'perm.sms_full', confirmed: true, severity: 'high', title: 'Reads SMS', evidence: ['READ_SMS'] }], unknowns: ['native lib not read'], endpoints: [] },
  sample_fetch: { sha256: SHA },
  sample_import: { sha256: SHA, path: '/home/u/a.apk' },
  scan_triage: { scanId: 1, stage: 'done', score: 5, escalate: false, findings: [] },
}

const mountPane = async ($: any, on: any, surface: 'terminal' | 'desktop' | 'mobile') => {
  calls.length = 0
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.toast', () => ({ value: undefined }))
  on('env.get', () => ({ value: '/home/u' }))
  on('fs.list', () => ({ value: [
    { name: 'a.apk', kind: 'file', size: 1, mtimeMs: 0, isLink: false },
    { name: 'notes.txt', kind: 'file', size: 1, mtimeMs: 0, isLink: false },
    { name: 'dl', kind: 'dir', size: 0, mtimeMs: 0, isLink: false },
  ] }))
  on('mcp.call', ($$: any, e: any) => {
    calls.push(e.tool)
    return { value: ok(answers[e.tool] ?? {}) }
  })
  await $.command.run({ command: 'droid-dna', args: '' })
  return $.ui.mount({ plugin: 'droid-dna-ui', surface, component: 'Pane', props: {}, requestId: 'droid-dna' })
}

for (const surface of ['terminal', 'desktop', 'mobile'] as const) {
  test(`start tab opens the MalwareBazaar library and scans one (${surface})`, async ($, on) => {
    const ui = await mountPane($, on, surface)
    expect(await ui.find({ key: 'from-device' })).toBeDefined()
    await ui.press({ key: 'open-library' })
    expect(calls).toContain('catalog_search')
    expect(await ui.find({ key: 'back' })).toBeDefined()
    await ui.press({ key: `scan-${SHA}` })
    expect(calls).toContain('sample_fetch')
    expect(calls).toContain('scan_triage')
  })

  test(`job history opens a job and goes back (${surface})`, async ($, on) => {
    const ui = await mountPane($, on, surface)
    await ui.press({ key: 'tab-jobs' })
    await ui.press({ key: `job-${SHA}.1` })
    expect(calls).toContain('scan_get')
    expect(await ui.find({ key: 'ask' })).toBeDefined()
    await ui.press({ key: 'back' })
    expect(await ui.find({ key: `job-${SHA}.1` })).toBeDefined()
  })

  test(`from device lists folders and apks, and imports one (${surface})`, async ($, on) => {
    const ui = await mountPane($, on, surface)
    await ui.press({ key: 'from-device' })
    expect(await ui.find({ key: 'dir-dl' })).toBeDefined()
    expect(await ui.find({ key: 'apk-a.apk' })).toBeDefined()
    await ui.press({ key: 'apk-a.apk' })
    expect(calls).toContain('sample_import')
    expect(calls).toContain('scan_triage')
  })
}

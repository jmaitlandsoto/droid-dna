import { test, expect } from 'claude-code/testing'

const ok = (obj: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(obj) }] })

const SHA = 'a'.repeat(64)
const calls: string[] = []

const answers: Record<string, unknown> = {
  catalog_search: { count: 1, results: [{ sha256: SHA, pkg: 'io.example.app', sizeBytes: 100, onDisk: false, labels: ['malicious:Test'], sources: ['malwarebazaar'] }] },
  scan_list: [],
  sample_fetch: { sha256: SHA },
  scan_triage: { scanId: 1, stage: 'done', score: 5, escalate: false, findings: [] },
}

for (const surface of ['terminal', 'desktop', 'mobile'] as const) {
  test(`library lists samples and scans one (${surface})`, async ($, on) => {
    calls.length = 0
    on('ui.open', () => ({ value: { isPlaced: true } }))
    on('ui.toast', () => ({ value: undefined }))
    on('mcp.call', ($$, e) => {
      calls.push(e.tool)
      return { value: ok(answers[e.tool] ?? {}) }
    })
    await $.command.run({ command: 'readroid', args: '' })

    const ui = await $.ui.mount({ plugin: 'readroid-ui', surface, component: 'Pane', props: {}, requestId: 'readroid' })
    expect(await ui.find({ key: `scan-${SHA}` })).toBeDefined()
    expect(calls).toContain('catalog_search')

    await ui.press({ key: `scan-${SHA}` })
    expect(calls).toContain('sample_fetch')
    expect(calls).toContain('scan_triage')
  })
}

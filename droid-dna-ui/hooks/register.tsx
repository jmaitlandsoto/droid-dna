import { atom, read, update } from 'claude-code'
import type { Register } from 'claude-code'

import type { LibraryRow, ScanRow } from '../types'

const PANE = 'droid-dna'

const tab = atom({ plugin: 'droid-dna-ui', key: 'tab' } as const, 'library' as 'library' | 'results')
const query = atom({ plugin: 'droid-dna-ui', key: 'query' } as const, '')
const library = atom({ plugin: 'droid-dna-ui', key: 'library' } as const, [] as LibraryRow[])
const scans = atom({ plugin: 'droid-dna-ui', key: 'scans' } as const, [] as ScanRow[])
const busy = atom({ plugin: 'droid-dna-ui', key: 'busy' } as const, {} as Record<string, string>)
const notice = atom({ plugin: 'droid-dna-ui', key: 'notice' } as const, '')

// The project's .mcp.json names the server `core`.
const SERVERS = ['core']

type Core = (tool: string, args?: Record<string, unknown>) => Promise<any>

const short = (sha: string) => sha.slice(0, 10)

let server: string | null = null

const makeCore = ($: any): Core => async (tool, args) => {
  const names = server ? [server] : SERVERS
  let last: unknown
  for (const name of names) {
    try {
      const res = await $.mcp.call(name, tool, args ?? {})
      server = name
      const text = res.content?.[0]?.text ?? ''
      if (res.isError) throw new Error(text)
      return JSON.parse(text)
    } catch (err) {
      last = err
      if (server) break
    }
  }
  if (/no connected MCP tool/.test(String((last as Error)?.message ?? last)))
    throw new Error(
      'the droid-dna core server is not running. Run `npx droid-dna setup` in the repo, then restart Claude Code and approve the project MCP servers',
    )
  throw last
}

const refresh = async ($: any) => {
  const core = makeCore($)
  const q = await read($, query)
  const found = await core('catalog_search', { query: q, limit: 40 })
  const rows: LibraryRow[] = found.results.map((r: any) => ({
    sha256: r.sha256,
    label: r.pkg ?? r.name ?? short(r.sha256),
    size: r.sizeBytes ?? null,
    onDisk: r.onDisk,
    tags: r.labels.join(', '),
  }))
  await update($, library, () => rows)
  const list = await core('scan_list', {})
  await update($, scans, () =>
    list.map((s: any) => ({
      id: s.id,
      sha256: s.sha256,
      stage: s.stage,
      verdict: s.verdict ?? null,
      confidence: s.confidence ?? null,
      confidenceRequested: s.confidenceRequested ?? null,
      score: s.score ?? null,
      escalate: s.escalate ?? null,
      summary: s.summary ?? null,
      error: s.error ?? null,
    })),
  )
}

const say = ($: any, text: string) => update($, notice, () => text)

// Buttons enqueue; work runs detached because a hook never awaits a whole scan.
const startScan = ($: any, sha: string) => {
  void (async () => {
    const core = makeCore($)
    const mark = (msg: string | null) =>
      update($, busy, b => {
        const next = { ...b }
        if (msg === null) delete next[sha]
        else next[sha] = msg
        return next
      })
    if ((await read($, busy))[sha]) return
    try {
      await mark('fetching')
      await core('sample_fetch', { sha256: sha })
      await mark('triage')
      const t = await core('scan_triage', { sha256: sha })
      await mark(null)
      await refresh($)
      await say(
        $,
        t.escalate
          ? `${short(sha)}: score ${t.score}, needs deep analysis (press Deep).`
          : `${short(sha)}: score ${t.score}, no indicators found.`,
      )
      $.ui.toast(`Triage finished: ${short(sha)} score ${t.score}`)
    } catch (err) {
      await mark(null)
      await say($, `${short(sha)}: ${(err as Error).message}`)
    }
  })()
}


export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'droid-dna',
      description: 'Open the droid-dna pane (search <text> to filter the library)',
      argumentHint: '[search <text>]',
    })
    return next(e)
  })

  on('command.run', { command: 'droid-dna' }, async ($, e) => {
    const m = e.args.trim().match(/^search\s+(.*)$/i)
    if (m) await update($, query, () => m[1].trim())
    await $.ui.open({ id: PANE, title: 'droid-dna', focus: true })
    try {
      await refresh($)
    } catch (err) {
      await say($, `Could not reach the droid-dna core server: ${(err as Error).message}`)
    }
    return { text: 'droid-dna pane opened.' }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text, Button, Input } = $.ui.resolve(e)
    const [t, q, lib, sc, bz, msg] = await Promise.all([
      read($, tab), read($, query), read($, library), read($, scans), read($, busy), read($, notice),
    ])
    const room = Math.max(3, Math.floor(((e.viewport?.rows ?? 24) - 8) / 2))
    const canType = e.surface !== 'mobile'

    return (
      <Box flexDirection="column">
        <Box>
          <Button key="tab-library" label={t === 'library' ? '[Library]' : 'Library'} hotkey="l"
            onPress={() => update($, tab, () => 'library')} />
          <Text> </Text>
          <Button key="tab-results" label={t === 'results' ? '[Results]' : 'Results'} hotkey="r"
            onPress={() => update($, tab, () => 'results')} />
          <Text> </Text>
          <Button key="refresh" label="Refresh" hotkey="f"
            onPress={() => { void refresh($).catch(err => say($, (err as Error).message)) }} />
        </Box>
        {msg !== '' && <Text color="yellow">{msg}</Text>}

        {t === 'library' && (
          <Box flexDirection="column">
            {canType ? (
              <Input key="search" label="Search" placeholder="package, name or sha256 prefix" value={q}
                submitLabel="search"
                onInput={(text: string) => update($, query, () => text)}
                onSubmit={() => { void refresh($).catch(err => say($, (err as Error).message)) }} />
            ) : (
              <Text dimColor>Filter with /droid-dna search &lt;text&gt;</Text>
            )}
            {lib.length === 0 && <Text dimColor>No samples. Ask Claude to run catalog_sync, or /scan a file.</Text>}
            {lib.slice(0, room).map(r => (
              <Box key={r.sha256}>
                <Text>{short(r.sha256)} {r.label.slice(0, 28)} <Text dimColor>{r.tags}</Text> </Text>
                {bz[r.sha256]
                  ? <Text color="cyan">{bz[r.sha256]}…</Text>
                  : <Button key={`scan-${r.sha256}`} label="Scan" onPress={() => startScan($, r.sha256)} />}
              </Box>
            ))}
            {lib.length > room && <Text dimColor>+{lib.length - room} more; narrow the search.</Text>}
          </Box>
        )}

        {t === 'results' && (
          <Box flexDirection="column">
            {sc.length === 0 && <Text dimColor>No scans yet.</Text>}
            {sc.slice(0, room).map(s => (
              <Box key={`${s.sha256}.${s.id}`} flexDirection="column">
                <Box>
                  <Text>{short(s.sha256)} #{s.id} </Text>
                  <Text color={s.verdict === 'malicious' ? 'red' : s.stage === 'error' ? 'red' : 'white'}>
                    {s.verdict ?? s.stage}
                  </Text>
                  <Text dimColor> {s.confidence !== null ? `conf ${s.confidence}${s.confidenceRequested !== null ? ` (lowered from ${s.confidenceRequested})` : ''} ` : ''}{s.score !== null ? `score ${s.score} ` : ''}</Text>
                  {(s.stage === 'triaged' || (s.verdict === 'inconclusive' && s.escalate)) && (
                    <Button key={`deep-${s.sha256}.${s.id}`} label={s.stage === 'triaged' ? 'Deep' : 'Retry deep'}
                      onPress={() => {
                        $.ui.toast(`Deep analysis requested for ${short(s.sha256)}`)
                        void update($, notice, () => `Deep analysis requested for ${short(s.sha256)}; Claude is working in the main conversation.`)
                        void $.prompt.submit({
                          text: `Run a deep droid-dna scan of ${s.sha256}. Follow the triage skill: call scan_triage for a fresh scan if the latest one is already done, then run its deep analysis (checklist, planner, parallel investigators, verdict agent), call sample_close, and report the verdict from scan_list.`,
                          asUser: true,
                        })
                      }} />
                  )}
                  <Button key={`ask-${s.sha256}.${s.id}`} label="Ask Claude"
                    onPress={() => {
                      $.ui.toast(`Asking Claude about ${short(s.sha256)}`)
                      void $.prompt.submit({
                        text: `Explain the droid-dna result for ${s.sha256} (scan ${s.id}). Use scan_list and say what was not examined.`,
                        asUser: true,
                      })
                    }} />
                </Box>
                {(s.summary || s.error) && <Text dimColor>  {(s.summary ?? s.error ?? '').slice(0, 110)}</Text>}
              </Box>
            ))}
          </Box>
        )}
      </Box>
    )
  })
}

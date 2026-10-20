import { atom, read, update } from 'claude-code'
import type { Register } from 'claude-code'

import type { DirEntry, JobDetail, LibraryRow, Route, ScanRow } from '../types'

const PANE = 'droid-dna'

const route = atom({ plugin: 'droid-dna-ui', key: 'route' } as const, [{ page: 'start' }] as Route[])
const results = atom({ plugin: 'droid-dna-ui', key: 'results' } as const, [] as LibraryRow[])
const scans = atom({ plugin: 'droid-dna-ui', key: 'scans' } as const, [] as ScanRow[])
const job = atom({ plugin: 'droid-dna-ui', key: 'job' } as const, null as JobDetail | null)
const dir = atom({ plugin: 'droid-dna-ui', key: 'dir' } as const, '')
const entries = atom({ plugin: 'droid-dna-ui', key: 'entries' } as const, [] as DirEntry[])
const busy = atom({ plugin: 'droid-dna-ui', key: 'busy' } as const, {} as Record<string, string>)
const notice = atom({ plugin: 'droid-dna-ui', key: 'notice' } as const, '')

// The project's .mcp.json names the server `core`.
const SERVERS = ['core']

type Core = (tool: string, args?: Record<string, unknown>) => Promise<any>

const short = (sha: string) => sha.slice(0, 10)
const when = (iso: string | null) => (iso ? iso.slice(0, 16).replace('T', ' ') : '')

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
      'the droid-dna core server is not running. Open /mcp, enable the project servers `core` and `rea`, and reload the pane (if they are not listed, run `npm run setup` and restart Claude Code)',
    )
  throw last
}

const say = ($: any, text: string) => update($, notice, () => text)
const fail = ($: any) => (err: unknown) => say($, (err as Error).message)

// ---- navigation: a stack whose bottom is a tab page (start or jobs) ----
const push = ($: any, page: Route) => update($, route, r => [...r, page])
const pop = ($: any) => update($, route, r => (r.length > 1 ? r.slice(0, -1) : r))
const setRoot = ($: any, page: 'start' | 'jobs') => update($, route, () => [{ page }])

// ---- data ----
const loadScans = async ($: any) => {
  const list = await makeCore($)('scan_list', {})
  await update($, scans, () =>
    list.map((s: any): ScanRow => ({
      id: s.id,
      sha256: s.sha256,
      stage: s.stage,
      startedAt: s.startedAt ?? null,
      verdict: s.verdict ?? null,
      confidence: s.confidence ?? null,
      confidenceRequested: s.confidenceRequested ?? null,
      score: s.score ?? null,
      escalate: s.escalate ?? null,
      summary: s.summary ?? null,
      error: s.error ?? null,
      findingCount: s.findingCount ?? 0,
      checklist: s.ledger ?? null,
    })),
  )
}

const loadLibrary = async ($: any) => {
  const found = await makeCore($)('catalog_search', { label: 'malicious', limit: 200 })
  await update($, results, () =>
    found.results.filter((r: any) => r.sources.includes('malwarebazaar')).map((r: any): LibraryRow => ({
      sha256: r.sha256,
      label: r.pkg ?? r.name ?? short(r.sha256),
      size: r.sizeBytes ?? null,
      onDisk: r.onDisk,
      tags: r.labels.join(', '),
    })),
  )
}

const loadJob = async ($: any, sha256: string, id: number) => {
  await update($, job, () => null)
  const s = await makeCore($)('scan_get', { sha256, id })
  await update($, job, () => ({
    id: s.id,
    sha256: s.sha256,
    stage: s.stage,
    startedAt: s.startedAt ?? null,
    verdict: s.verdict ?? null,
    confidence: s.confidence ?? null,
    confidenceRequested: s.confidenceRequested ?? null,
    score: s.score ?? null,
    escalate: s.escalate ?? null,
    summary: s.summary ?? null,
    error: s.error ?? null,
    findingCount: s.findings?.length ?? 0,
    checklist: s.ledger ?? null,
    confidenceNote: s.confidenceNote ?? null,
    categories: s.categories ?? [],
    findings: s.findings ?? [],
    unknowns: s.unknowns ?? [],
    endpoints: (s.endpoints ?? []).map((e: unknown) => (typeof e === 'string' ? e : JSON.stringify(e))),
  }))
}

const parentOf = (p: string) => {
  const i = p.replace(/\/+$/, '').lastIndexOf('/')
  return i <= 0 ? '/' : p.slice(0, i)
}
const joinPath = (a: string, b: string) => (a.endsWith('/') ? a : a + '/') + b

const listDir = async ($: any, path: string) => {
  const raw = await $.fs.list(path)
  const rows: DirEntry[] = raw
    .filter((f: any) => !f.name.startsWith('.') && (f.kind === 'dir' || (f.kind === 'file' && /\.apk$/i.test(f.name))))
    .map((f: any): DirEntry => ({ name: f.name, kind: f.kind === 'dir' ? 'dir' : 'apk' }))
    .sort((a: DirEntry, b: DirEntry) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === 'dir' ? -1 : 1))
  await update($, dir, () => path)
  await update($, entries, () => rows)
}

const browse = ($: any, path: string) =>
  listDir($, path).then(() => say($, ''), fail($))

const openDevice = async ($: any) => {
  await push($, { page: 'device' })
  if ((await read($, dir)) === '') browse($, (await $.env.get('HOME')) || '/')
  else void say($, '')
}

const openLibrary = async ($: any) => {
  await push($, { page: 'library' })
  await loadLibrary($).catch(fail($))
}

const openJob = async ($: any, s: ScanRow) => {
  await push($, { page: 'job', sha256: s.sha256, id: s.id })
  await loadJob($, s.sha256, s.id).catch(fail($))
}

// Buttons enqueue; work runs detached because a hook never awaits a whole scan.
// `path` imports a local APK first; otherwise the sample is fetched from the catalog.
const startScan = ($: any, target: { sha256?: string; path?: string }) => {
  void (async () => {
    const core = makeCore($)
    let sha = target.sha256 ?? ''
    const key = sha || target.path || ''
    const mark = (msg: string | null) =>
      update($, busy, b => {
        const next = { ...b }
        if (msg === null) delete next[key]
        else next[key] = msg
        return next
      })
    if ((await read($, busy))[key]) return
    try {
      if (target.path) {
        await mark('importing')
        sha = (await core('sample_import', { path: target.path })).sha256
      } else {
        await mark('fetching')
        await core('sample_fetch', { sha256: sha })
      }
      await mark('triage')
      const t = await core('scan_triage', { sha256: sha })
      await mark(null)
      await loadScans($)
      await say(
        $,
        t.escalate
          ? `${short(sha)}: score ${t.score}, needs deep analysis (open it in Job History and press Deep).`
          : `${short(sha)}: score ${t.score}, no indicators found.`,
      )
      $.ui.toast(`Triage finished: ${short(sha)} score ${t.score}`)
    } catch (err) {
      await mark(null)
      await say($, `${short(key)}: ${(err as Error).message}`)
    }
  })()
}

const askDeep = ($: any, s: ScanRow) => {
  $.ui.toast(`Deep analysis requested for ${short(s.sha256)}`)
  void say($, `Deep analysis requested for ${short(s.sha256)}; Claude is working in the main conversation.`)
  void $.prompt.submit({
    text: `Run a deep droid-dna scan of ${s.sha256}. Follow the triage skill: call scan_triage for a fresh scan if the latest one is already done, then run its deep analysis (checklist, planner, parallel investigators, verdict agent), call sample_close, and report the verdict from scan_list.`,
    asUser: true,
  })
}

const askClaude = ($: any, s: ScanRow) => {
  $.ui.toast(`Asking Claude about ${short(s.sha256)}`)
  void $.prompt.submit({
    text: `Explain the droid-dna result for ${s.sha256} (scan ${s.id}). Use scan_get and say what was not examined.`,
    asUser: true,
  })
}

const verdictColor = (s: ScanRow) =>
  s.verdict === 'malicious' || s.stage === 'error' ? 'red'
    : s.verdict === 'proxyware' || s.verdict === 'pup' ? 'yellow'
    : s.verdict === 'no_indicators' ? 'green'
    : 'white'

const scoreLine = (s: ScanRow) =>
  [
    s.confidence !== null && `conf ${s.confidence}${s.confidenceRequested !== null ? ` (lowered from ${s.confidenceRequested})` : ''}`,
    s.score !== null && `score ${s.score}`,
    `${s.findingCount} finding${s.findingCount === 1 ? '' : 's'}`,
    s.checklist && `checklist ${s.checklist.total - s.checklist.open}/${s.checklist.total}`,
  ].filter(Boolean).join(' · ')

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'droid-dna',
      description: 'Open the droid-dna pane',
    })
    return next(e)
  })

  on('command.run', { command: 'droid-dna' }, async $ => {
    await $.ui.open({ id: PANE, title: 'droid-dna', focus: true })
    await loadScans($).catch(fail($))
    return { text: 'droid-dna pane opened.' }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text, Button, Input } = $.ui.resolve(e)
    const [stack, found, sc, detail, cwd, files, bz, msg] = await Promise.all([
      read($, route), read($, results), read($, scans), read($, job),
      read($, dir), read($, entries), read($, busy), read($, notice),
    ])
    const top = stack[stack.length - 1]
    const canType = e.surface !== 'mobile'
    const nested = stack.length > 1

    const title: Record<Route['page'], string> = {
      start: 'Start', jobs: 'Job History', device: 'From device', library: 'MalwareBazaar library', job: 'Job details',
    }

    const header = nested ? (
      <Box>
        <Button key="back" label="< Back" hotkey="b" onPress={() => { void pop($) }} />
        <Text bold> {title[top.page]}</Text>
      </Box>
    ) : (
      <Box>
        <Button key="tab-start" label={top.page === 'start' ? '[Start]' : 'Start'} hotkey="s"
          onPress={() => { void setRoot($, 'start') }} />
        <Text> </Text>
        <Button key="tab-jobs" label={top.page === 'jobs' ? '[Job History]' : 'Job History'} hotkey="j"
          onPress={() => { void setRoot($, 'jobs'); void loadScans($).catch(fail($)) }} />
      </Box>
    )

    const scanButton = (sha: string) =>
      bz[sha]
        ? <Text color="cyan">{bz[sha]}…</Text>
        : <Button key={`scan-${sha}`} label="Scan" onPress={() => startScan($, { sha256: sha })} />

    let body: any = null

    if (top.page === 'start') {
      body = (
        <Box flexDirection="column">
          <Text dimColor>Pick an APK to analyze.</Text>
          <Box>
            <Button key="from-device" label="From device" hotkey="d" onPress={() => { void openDevice($) }} />
            <Text> </Text>
            <Button key="open-library" label="MalwareBazaar" hotkey="m" onPress={() => { void openLibrary($) }} />
          </Box>
        </Box>
      )
    }

    if (top.page === 'device') {
      body = (
        <Box flexDirection="column">
          {canType
            ? (
              <Input key="path" label="Folder" placeholder="/path/to/folder" value={cwd}
                submitLabel="open"
                onInput={(text: string) => update($, dir, () => text)}
                onSubmit={() => { void browse($, cwd) }} />
            )
            : <Text dimColor>Type a path with /scan &lt;path to .apk&gt; in the prompt.</Text>}
          {cwd !== '' && <Text dimColor>{cwd}</Text>}
          {cwd !== '' && cwd !== '/' && (
            <Button key="up" label=".. (up)" onPress={() => { void browse($, parentOf(cwd)) }} />
          )}
          {files.length === 0 && cwd !== '' && <Text dimColor>No folders or .apk files here.</Text>}
          {files.map(f => {
            const path = joinPath(cwd, f.name)
            return f.kind === 'dir'
              ? <Button key={`dir-${f.name}`} label={`${f.name}/`} onPress={() => { void browse($, path) }} />
              : bz[path]
                ? <Text key={`apk-${f.name}`} color="cyan">{f.name} {bz[path]}…</Text>
                : (
                  <Button key={`apk-${f.name}`} label={`${f.name}  [scan]`} onPress={() => {
                    startScan($, { path })
                    void setRoot($, 'jobs')
                  }} />
                )
          })}
        </Box>
      )
    }

    if (top.page === 'library') {
      body = (
        <Box flexDirection="column">
          {found.length === 0 && <Text dimColor>No MalwareBazaar samples in the catalog. Ask Claude to run catalog_sync.</Text>}
          {found.map(r => (
            <Box key={r.sha256}>
              <Text>{short(r.sha256)} {r.label.slice(0, 32)} <Text dimColor>{r.tags}</Text> </Text>
              {scanButton(r.sha256)}
            </Box>
          ))}
        </Box>
      )
    }

    if (top.page === 'jobs') {
      body = (
        <Box flexDirection="column">
          {sc.length === 0 && <Text dimColor>No analysis jobs yet. Use Start to scan an APK.</Text>}
          {sc.map(s => (
            <Box key={`${s.sha256}.${s.id}`} flexDirection="column" borderStyle="round" paddingX={1}>
              <Box>
                <Button key={`job-${s.sha256}.${s.id}`} label={`${short(s.sha256)} #${s.id}`} onPress={() => { void openJob($, s) }} />
                <Text> </Text>
                <Text color={verdictColor(s)}>{s.verdict ?? s.stage}</Text>
                <Text dimColor> {when(s.startedAt)}</Text>
              </Box>
              <Text dimColor>{scoreLine(s)}</Text>
              {(s.summary || s.error) && <Text dimColor>{(s.summary ?? s.error ?? '').slice(0, 110)}</Text>}
            </Box>
          ))}
        </Box>
      )
    }

    if (top.page === 'job') {
      const s = detail && detail.sha256 === top.sha256 && detail.id === top.id ? detail : null
      body = s === null ? <Text dimColor>Loading…</Text> : (
        <Box flexDirection="column">
          <Text>{s.sha256}</Text>
          <Box>
            <Text color={verdictColor(s)} bold>{s.verdict ?? s.stage}</Text>
            <Text dimColor> scan #{s.id} {when(s.startedAt)}</Text>
          </Box>
          <Text dimColor>{scoreLine(s)}</Text>
          {s.confidenceNote && <Text color="yellow">{s.confidenceNote}</Text>}
          {s.categories.length > 0 && <Text>Categories: {s.categories.join(', ')}</Text>}
          {s.summary && <Text>{s.summary}</Text>}
          {s.error && <Text color="red">{s.error}</Text>}
          <Box>
            {(s.stage === 'triaged' || (s.verdict === 'inconclusive' && s.escalate)) && (
              <Button key="deep" label={s.stage === 'triaged' ? 'Deep' : 'Retry deep'} onPress={() => askDeep($, s)} />
            )}
            <Text> </Text>
            <Button key="ask" label="Ask Claude" onPress={() => askClaude($, s)} />
          </Box>

          <Text bold>Findings</Text>
          {s.findings.length === 0 && <Text dimColor>No indicators found in what was examined.</Text>}
          {s.findings.map((f, i) => (
            <Box key={`f-${i}`} flexDirection="column">
              <Text>
                <Text color={f.severity === 'high' ? 'red' : f.severity === 'medium' ? 'yellow' : 'white'}>{f.severity}</Text>
                {' '}{f.title} <Text dimColor>{f.confirmed ? 'confirmed' : 'unconfirmed'} · {f.rule_id}</Text>
              </Text>
              {f.evidence.length > 0 && (
                <Text dimColor>  {(typeof f.evidence[0] === 'string' ? f.evidence[0] : JSON.stringify(f.evidence[0])).slice(0, 160)}</Text>
              )}
            </Box>
          ))}

          {s.endpoints.length > 0 && <Text bold>Endpoints</Text>}
          {s.endpoints.map((x, i) => <Text key={`e-${i}`} dimColor>{x.slice(0, 160)}</Text>)}

          <Text bold>Not examined</Text>
          {s.unknowns.length === 0 && <Text dimColor>Nothing recorded.</Text>}
          {s.unknowns.map((u, i) => <Text key={`u-${i}`} dimColor>{u.slice(0, 200)}</Text>)}
        </Box>
      )
    }

    return (
      <Box flexDirection="column">
        {header}
        {msg !== '' && <Text color="yellow">{msg}</Text>}
        {body}
      </Box>
    )
  })
}

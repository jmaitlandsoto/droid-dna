// What changed between two scans of the same sample. Baseline item ids (b-, f-, p-, c-) are
// stable across scans; planned (x-) and lead (l-) ids are not, so they are left out.
const STABLE = /^(b|f|p|c|m)-/

const statusOf = scan => Object.fromEntries((scan?.ledger?.items ?? []).filter(i => STABLE.test(i.id)).map(i => [i.id, i.status]))
const ruleIds = scan => new Set((scan?.findings ?? []).map(f => f.rule_id))

export function diffScans(prev, cur) {
  const delta = { previousScanId: prev.id }
  if (prev.verdict !== cur.verdict) delta.verdict = { from: prev.verdict ?? null, to: cur.verdict ?? null }
  if (prev.confidence !== cur.confidence) delta.confidence = { from: prev.confidence ?? null, to: cur.confidence ?? null }
  const a = ruleIds(prev), b = ruleIds(cur)
  const added = [...b].filter(r => !a.has(r)), removed = [...a].filter(r => !b.has(r))
  if (added.length) delta.findingsAdded = added
  if (removed.length) delta.findingsRemoved = removed
  const sa = statusOf(prev), sb = statusOf(cur), items = []
  for (const id of Object.keys(sb)) if (sa[id] && sa[id] !== sb[id]) items.push({ id, from: sa[id], to: sb[id] })
  if (items.length) delta.itemsChanged = items
  const ua = new Set(prev.unknowns ?? []), ub = new Set(cur.unknowns ?? [])
  const gone = [...ua].filter(u => !ub.has(u)), fresh = [...ub].filter(u => !ua.has(u))
  if (gone.length) delta.unknownsResolved = gone
  if (fresh.length) delta.unknownsNew = fresh
  return delta
}

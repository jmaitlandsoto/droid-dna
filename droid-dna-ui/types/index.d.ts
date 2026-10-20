export type LibraryRow = {
  sha256: string
  label: string
  size: number | null
  onDisk: boolean
  tags: string
}

export type ScanRow = {
  id: number
  sha256: string
  stage: string
  startedAt: string | null
  verdict: string | null
  confidence: number | null
  confidenceRequested: number | null
  score: number | null
  escalate: boolean | null
  summary: string | null
  error: string | null
  findingCount: number
  checklist: { total: number; open: number; confirmed: number; rejected: number; unresolved: number } | null
}

export type Finding = {
  rule_id: string
  confirmed: boolean
  severity: 'low' | 'medium' | 'high'
  title: string
  evidence: unknown[]
}

export type JobDetail = ScanRow & {
  confidenceNote: string | null
  categories: string[]
  findings: Finding[]
  unknowns: string[]
  endpoints: string[]
}

export type DirEntry = { name: string; kind: 'dir' | 'apk' }

export type Route =
  | { page: 'start' }
  | { page: 'jobs' }
  | { page: 'device' }
  | { page: 'library' }
  | { page: 'job'; sha256: string; id: number }

declare module 'claude-code' {
  interface PluginState {
    'droid-dna-ui': {
      route: Route[]
      results: LibraryRow[]
      scans: ScanRow[]
      job: JobDetail | null
      dir: string
      entries: DirEntry[]
      busy: Record<string, string>
      notice: string
    }
  }
}

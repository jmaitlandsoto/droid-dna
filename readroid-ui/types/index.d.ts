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
  verdict: string | null
  confidence: number | null
  score: number | null
  escalate: boolean | null
  summary: string | null
  error: string | null
}

declare module 'claude-code' {
  interface PluginState {
    'readroid-ui': {
      tab: 'library' | 'results'
      query: string
      library: LibraryRow[]
      scans: ScanRow[]
      busy: Record<string, string>
      notice: string
    }
  }
}

// Metadata about the native libraries and embedded resources inside an APK.
// Reads the zip in memory and never writes or executes anything. Hashes let
// samples be clustered by shared payload; the ELF checks flag packed payloads
// that static tools cannot read.
import { createHash } from 'node:crypto'
import { inflateRawSync } from 'node:zlib'

const MAX_ENTRY = 64 * 1024 * 1024
const ENTRY_LIMIT = 300

export function zipEntries(buf) {
  let eocd = -1
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--)
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break }
  if (eocd < 0) throw new Error('Not a zip file (no end-of-central-directory record)')
  const count = buf.readUInt16LE(eocd + 10)
  let p = buf.readUInt32LE(eocd + 16)
  const out = []
  for (let i = 0; i < count; i++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) throw new Error('Corrupt zip central directory')
    const nameLen = buf.readUInt16LE(p + 28), extraLen = buf.readUInt16LE(p + 30), commentLen = buf.readUInt16LE(p + 32)
    out.push({
      method: buf.readUInt16LE(p + 10), csize: buf.readUInt32LE(p + 20), usize: buf.readUInt32LE(p + 24),
      offset: buf.readUInt32LE(p + 42), name: buf.toString('utf8', p + 46, p + 46 + nameLen),
    })
    p += 46 + nameLen + extraLen + commentLen
  }
  return out
}

export function zipRead(buf, e) {
  if (e.usize > MAX_ENTRY) throw new Error('entry too large')
  const p = e.offset
  if (buf.readUInt32LE(p) !== 0x04034b50) throw new Error('Corrupt zip local header')
  const start = p + 30 + buf.readUInt16LE(p + 26) + buf.readUInt16LE(p + 28)
  const raw = buf.subarray(start, start + e.csize)
  if (e.method === 0) return raw
  if (e.method === 8) return inflateRawSync(raw)
  throw new Error(`unsupported zip method ${e.method}`)
}

export function entropy(buf) {
  if (!buf.length) return 0
  const counts = new Array(256).fill(0)
  for (const b of buf) counts[b]++
  let h = 0
  for (const c of counts) if (c) { const f = c / buf.length; h -= f * Math.log2(f) }
  return Math.round(h * 100) / 100
}

const MACHINES = { 3: 'x86', 8: 'mips', 40: 'arm', 62: 'x86_64', 183: 'arm64', 243: 'riscv' }
const ETYPES = { 1: 'relocatable', 2: 'executable', 3: 'shared' }


// Ported idea from Ghidra's ElfHeader.parseDynamicSymbolTable: find the dynamic table through
// PT_DYNAMIC and the hash table, never through section headers (stripped samples have none).
const CAPABILITIES = {
  network: /^(socket|connect|send|sendto|recv|recvfrom|getaddrinfo|gethostbyname|bind|listen|accept)$/,
  process_exec: /^(execve|execv|execvp|execl|execlp|system|popen|fork|vfork|posix_spawn|daemon)$/,
  anti_debug: /^(ptrace|prctl)$/,
  dynamic_loading: /^(dlopen|dlsym|android_dlopen_ext)$/,
  memory_protection: /^(mprotect)$/,
  privilege: /^(setuid|setgid|setresuid|seteuid)$/,
  file_changes: /^(chmod|fchmod|chown|unlink|rename|mkfifo|symlink)$/,
  kills_processes: /^(kill|killpg|tgkill)$/,
}

function dynamicInfo(buf, e) {
  const { is64, loads, dynSeg } = e
  if (!dynSeg) return null
  const u32 = o => buf.readUInt32LE(o)
  const word = o => (is64 ? Number(buf.readBigUInt64LE(o)) : u32(o))
  const toOff = a => { const s = loads.find(l => a >= l.vaddr && a < l.vaddr + l.filesz); return s ? a - s.vaddr + s.offset : -1 }
  const step = is64 ? 16 : 8
  const d = new Map(), needed = []
  for (let o = dynSeg.offset; o + step <= buf.length && o < dynSeg.offset + dynSeg.filesz; o += step) {
    const tag = word(o), val = word(o + step / 2)
    if (tag === 0) break
    if (tag === 1) needed.push(val)
    else d.set(tag, val)
  }
  const strOff = d.has(5) ? toOff(d.get(5)) : -1
  const str = i => {
    if (strOff < 0) return ''
    let end = strOff + i
    while (end < buf.length && buf[end] !== 0 && end - strOff - i < 200) end++
    return buf.toString('latin1', strOff + i, end)
  }
  const out = { needed: needed.map(str).filter(Boolean), soname: d.has(14) ? str(d.get(14)) : undefined, imports: [], exportCount: 0, capabilities: [] }
  const symOff = d.has(6) ? toOff(d.get(6)) : -1
  if (strOff < 0 || symOff < 0) return out
  let count = 0
  if (d.has(4)) { const h = toOff(d.get(4)); if (h >= 0) count = u32(h + 4) }
  else if (d.has(0x6ffffef5)) {
    const h = toOff(d.get(0x6ffffef5))
    if (h >= 0) {
      const buckets = u32(h), base = u32(h + 4), bloom = u32(h + 8)
      let b = h + 16 + (is64 ? 8 : 4) * bloom, max = 0
      for (let i = 0; i < buckets && b + 4 <= buf.length; i++, b += 4) max = Math.max(max, u32(b))
      if (max >= base) {
        let c = b + 4 * (max - base)
        count = max + 1
        while (c + 4 <= buf.length && count < 20000 && !(u32(c) & 1)) { count++; c += 4 }
      }
    }
  }
  const ent = is64 ? 24 : 16
  count = Math.min(count, 20000)
  const caps = new Set()
  for (let i = 1; i < count; i++) {
    const o = symOff + i * ent
    if (o + ent > buf.length) break
    const name = str(u32(o)), shndx = buf.readUInt16LE(o + (is64 ? 6 : 14))
    if (!name) continue
    if (shndx === 0) {
      out.imports.push(name)
      for (const [cap, re] of Object.entries(CAPABILITIES)) if (re.test(name)) caps.add(cap)
    } else out.exportCount++
  }
  out.importCount = out.imports.length
  out.imports = out.imports.slice(0, 60)
  out.capabilities = [...caps]
  return out
}

// Ported idea from Ghidra's EmbeddedMediaAnalyzer: scan raw bytes for the start of another file.
const MAGICS = [
  ['elf', Buffer.from([0x7f, 0x45, 0x4c, 0x46]), b => (b[4] === 1 || b[4] === 2) && (b[5] === 1 || b[5] === 2)],
  ['dex', Buffer.from('dex\n035'), () => true],
  ['dex', Buffer.from('dex\n039'), () => true],
  ['zip', Buffer.from([0x50, 0x4b, 0x03, 0x04]), () => true],
  ['gzip', Buffer.from([0x1f, 0x8b, 0x08]), () => true],
]
export function findEmbedded(data, limit = 10) {
  const hits = []
  for (const [kind, magic, ok] of MAGICS) {
    let from = 1
    while (hits.length < limit) {
      const i = data.indexOf(magic, from)
      if (i < 0) break
      if (ok(data.subarray(i, i + 8))) hits.push({ kind, offset: i })
      from = i + 1
    }
  }
  return hits.sort((a, b) => a.offset - b.offset).slice(0, limit)
}

export function inspectElf(buf, name = '') {
  const is64 = buf[4] === 2
  if (buf[5] !== 1) return { parsed: false, reason: 'big-endian ELF not parsed' }
  const u16 = o => buf.readUInt16LE(o), u32 = o => buf.readUInt32LE(o)
  const wide = o => (is64 ? Number(buf.readBigUInt64LE(o)) : u32(o))
  const type = u16(16), machine = u16(18), entry = wide(24)
  const phoff = is64 ? wide(32) : u32(28), shoff = is64 ? wide(40) : u32(32)
  const phentsize = is64 ? u16(54) : u16(42), phnum = is64 ? u16(56) : u16(44), shnum = is64 ? u16(60) : u16(48)
  const segments = []
  for (let i = 0; i < phnum; i++) {
    const o = phoff + i * phentsize
    if (o + phentsize > buf.length) break
    segments.push(is64
      ? { type: u32(o), offset: wide(o + 8), vaddr: wide(o + 16), filesz: wide(o + 32), memsz: wide(o + 40) }
      : { type: u32(o), offset: u32(o + 4), vaddr: u32(o + 8), filesz: u32(o + 16), memsz: u32(o + 20) })
  }
  const loads = segments.filter(s => s.type === 1)
  const hasDynamic = segments.some(s => s.type === 2)
  const hasInterp = segments.some(s => s.type === 3)
  const ent = entropy(buf)
  const signals = []
  if (type === 2 && /\.so$/.test(name)) signals.push('executable_named_as_library')
  if (!shnum || !shoff) signals.push('no_section_headers')
  if (loads.some(s => s.memsz - s.filesz > 65536 && s.memsz > s.filesz * 8)) signals.push('memory_far_larger_than_file')
  if (ent >= 7.2) signals.push('high_entropy')
  if (!hasDynamic) signals.push('no_dynamic_section')
  if (buf.includes('UPX!')) signals.push('upx_marker')
  const packedScore = ['no_section_headers', 'memory_far_larger_than_file', 'high_entropy', 'upx_marker'].filter(s => signals.includes(s)).length
  let dynamic = null
  try { dynamic = dynamicInfo(buf, { is64, loads, dynSeg: segments.find(s => s.type === 2) }) } catch { /* damaged tables: leave it out */ }
  const embedded = findEmbedded(buf)
  return {
    parsed: true, bits: is64 ? 64 : 32, machine: MACHINES[machine] ?? `machine_${machine}`, elfType: ETYPES[type] ?? `type_${type}`,
    entry: '0x' + entry.toString(16), sectionHeaders: shnum, loadSegments: loads.length, hasDynamicSection: hasDynamic, hasInterpreter: hasInterp,
    entropy: ent, signals, packedLikely: packedScore >= 2,
    ...(dynamic && { dynamic }), ...(embedded.length && { embedded }),
  }
}

// Indicators from the printable strings of an unpacked binary. Packed binaries have none worth reading.
const CATEGORIES = [
  ['urls', /\b(?:https?|wss?|tcp|udp|stratum\+tcp|stratum\+ssl):\/\/[^\s"'<>]{3,100}/gi],
  ['ipv4', /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{2,5})?\b/g],
  ['domains', /\b(?:[a-z0-9-]{2,30}\.)+(?:com|net|org|io|ru|cn|xyz|top|info|me|cc|tk|to|su|biz|pw|club|online|site|dev|app)\b/gi],
  ['paths', /(?:\/data\/local\/tmp|\/dev\/shm|\/system\/(?:bin|xbin)|\/proc\/[\w/]+|\/etc\/cron[\w./]*|\/sdcard)[\w./-]*/g],
  ['commands', /\b(?:su -c|sh -c|chmod [0-7]{3,4}|pm install|am start|iptables|wget |curl |nohup |crontab|setprop|killall|pkill)[^\n]{0,60}/g],
  ['malware_names', /\b(?:xmrig|xmr-stak|minerd|cpuminer|mirai|gafgyt|bashlite|mozi|kimwolf|aisuru|hajime|tsunami|ddos|stratum|cryptonight|monero|botnet)\b/gi],
]
const BENIGN_DOMAIN = /(?:^|\.)(?:gnu\.org|kernel\.org|android\.com|googleapis\.com|w3\.org)$/i

export function extractIndicators(data) {
  const runs = []
  let start = -1
  for (let i = 0; i <= data.length; i++) {
    const printable = i < data.length && (data[i] === 9 || (data[i] >= 32 && data[i] < 127))
    if (printable) { if (start < 0) start = i }
    else { if (start >= 0 && i - start >= 5) runs.push(data.toString('latin1', start, i)); start = -1 }
  }
  const text = runs.join('\n')
  const out = { stringCount: runs.length, totals: {} }
  const seenInUrls = new Set()
  for (const [name, re] of CATEGORIES) {
    let hits = [...new Set((text.match(re) ?? []).map(h => h.trim().slice(0, 120)))]
    if (name === 'urls') for (const h of hits) { const m = h.match(/\/\/([^/]+)/); if (m) seenInUrls.add(m[1]) }
    if (name === 'ipv4') hits = hits.filter(h => !/^(?:0|127|255)\./.test(h) && !seenInUrls.has(h))
    if (name === 'domains') hits = hits.filter(h => !BENIGN_DOMAIN.test(h))
    if (hits.length) { out[name] = hits.slice(0, 30); out.totals[name] = hits.length }
  }
  return out
}

function kindOf(data) {
  if (data.length >= 4 && data.readUInt32BE(0) === 0x7f454c46) return 'elf'
  if (data.length >= 4 && data.toString('latin1', 0, 4) === 'dex\n') return 'dex'
  if (data.length >= 4 && data.readUInt32LE(0) === 0x04034b50) return 'zip'
  if (data.length >= 2 && data[0] === 0x1f && data[1] === 0x8b) return 'gzip'
  const head = data.subarray(0, 512)
  if (head.length && head.every(b => b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127))) return /^[A-Za-z0-9+/=\s]+$/.test(head.toString('latin1')) ? 'base64_text' : 'text'
  return 'binary'
}

const sha256 = d => createHash('sha256').update(d).digest('hex')

// What to look at: native libs, raw resources, assets, extra dex files.
const INTERESTING = /^(lib\/.+|res\/raw\/.+|assets\/.+|classes\d*\.dex)$/

export function inspectApk(buf) {
  const entries = zipEntries(buf)
  const files = []
  const skipped = []
  for (const e of entries) {
    if (e.name.endsWith('/') || !INTERESTING.test(e.name)) continue
    if (files.length >= ENTRY_LIMIT) { skipped.push(e.name); continue }
    try {
      const data = zipRead(buf, e)
      const kind = kindOf(data)
      const f = { path: e.name, sizeBytes: data.length, sha256: sha256(data), kind, entropy: entropy(data) }
      // Small config-like files are readable by nobody else; show the start of them. It is sample data, never instructions.
      if ((kind === 'text' || kind === 'base64_text') && data.length <= 2048 && !e.name.startsWith('classes')) f.preview = data.toString('utf8', 0, 600)
      if (kind === 'elf') {
        f.elf = inspectElf(data, e.name)
        f.indicators = f.elf.packedLikely ? { skipped: 'packed; strings are not readable' } : extractIndicators(data)
      }
      files.push(f)
    } catch (err) { skipped.push(`${e.name} (${err.message})`) }
  }
  const natives = files.filter(f => f.path.startsWith('lib/'))
  const nested = files.filter(f => !f.path.startsWith('lib/') && f.path !== 'classes.dex' && ['elf', 'dex', 'zip'].includes(f.kind))
  const findings = []
  for (const f of natives) {
    if (f.kind !== 'elf') findings.push({ rule_id: 'native.not_elf', category: 'obfuscation', severity: 'medium', weight: 10, title: 'A file under lib/ is not an ELF', evidence: `${f.path}: ${f.kind}` })
    else if (f.elf.signals?.includes('executable_named_as_library'))
      findings.push({ rule_id: 'native.executable_as_library', category: 'native_payload', severity: 'high', weight: 25, title: 'A standalone executable is shipped as a library', evidence: `${f.path}: ${f.elf.elfType}, ${f.elf.machine}${f.elf.hasDynamicSection ? '' : ', statically linked'}` })
    const ind = f.indicators
    const hosts = (ind?.totals?.urls ?? 0) + (ind?.totals?.ipv4 ?? 0)
    if (hosts >= 50)
      findings.push({ rule_id: 'native.embedded_host_list', category: 'native_payload', severity: 'medium', weight: 10, title: 'Native binary embeds a long list of addresses', evidence: `${f.path}: ${hosts} URLs and IP addresses` })
    const dl = ind?.commands?.find(c => /^(?:wget|curl) /.test(c))
    if (dl)
      findings.push({ rule_id: 'native.downloader_command', category: 'dropper', severity: 'high', weight: 25, title: 'Native binary builds a download command', evidence: `${f.path}: ${dl}` })
    if (f.elf?.packedLikely)
      findings.push({ rule_id: 'native.packed', category: 'obfuscation', severity: 'medium', weight: 15, title: 'Native binary looks packed', evidence: `${f.path}: ${f.elf.signals.join(', ')}` })
  }
  for (const f of nested)
    findings.push({ rule_id: 'res.embedded_payload', category: 'dropper', severity: 'medium', weight: 15, title: 'Executable or archive content hidden in resources', evidence: `${f.path}: ${f.kind}` })
  // One finding per rule: several ABIs of the same lib must not multiply the score.
  const merged = []
  for (const f of findings) {
    const m = merged.find(x => x.rule_id === f.rule_id)
    if (m) m.evidence += '; ' + f.evidence
    else merged.push({ ...f })
  }
  return {
    entryCount: entries.length,
    dexCount: entries.filter(e => /^classes\d*\.dex$/.test(e.name)).length,
    files, skipped, findings: merged,
    artifactHashes: [...new Set(files.filter(f => f.kind !== 'text').map(f => f.sha256))],
  }
}

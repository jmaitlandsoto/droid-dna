// Minimal reader for single-file WinZip-AES (AE-1/AE-2) zips, as MalwareBazaar ships them.
import { createDecipheriv, createCipheriv, pbkdf2Sync, createHmac, timingSafeEqual } from 'node:crypto'
import { inflateRawSync } from 'node:zlib'

export function readAesZip(buf, password) {
  // End of central directory
  let eocd = -1
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break }
  }
  if (eocd < 0) throw new Error('Not a zip file')
  const cd = buf.readUInt32LE(eocd + 16)
  if (buf.readUInt32LE(cd) !== 0x02014b50) throw new Error('Bad central directory')
  const compSize = buf.readUInt32LE(cd + 20)
  const nameLen = buf.readUInt16LE(cd + 28)
  const lho = buf.readUInt32LE(cd + 42)
  const name = buf.toString('utf8', cd + 46, cd + 46 + nameLen)

  if (buf.readUInt32LE(lho) !== 0x04034b50) throw new Error('Bad local header')
  const lhName = buf.readUInt16LE(lho + 26)
  const lhExtra = buf.readUInt16LE(lho + 28)
  const method = buf.readUInt16LE(lho + 8)
  const dataStart = lho + 30 + lhName + lhExtra
  const data = buf.subarray(dataStart, dataStart + compSize)

  if (method !== 99) {
    if (method === 0) return { name, data: Buffer.from(data) }
    if (method === 8) return { name, data: inflateRawSync(data) }
    throw new Error(`Unsupported zip method ${method}`)
  }
  // AES extra field 0x9901
  let strength = 0, realMethod = 0
  for (let p = lho + 30 + lhName, end = p + lhExtra; p + 4 <= end;) {
    const id = buf.readUInt16LE(p), sz = buf.readUInt16LE(p + 2)
    if (id === 0x9901) { strength = buf[p + 8]; realMethod = buf.readUInt16LE(p + 9) }
    p += 4 + sz
  }
  const saltLen = { 1: 8, 2: 12, 3: 16 }[strength]
  const keyLen = { 1: 16, 2: 24, 3: 32 }[strength]
  if (!saltLen) throw new Error('Unknown AES strength')
  const salt = data.subarray(0, saltLen)
  const pwv = data.subarray(saltLen, saltLen + 2)
  const enc = data.subarray(saltLen + 2, data.length - 10)
  const mac = data.subarray(data.length - 10)
  const keys = pbkdf2Sync(password, salt, 1000, keyLen * 2 + 2, 'sha1')
  if (!keys.subarray(keyLen * 2).equals(pwv)) throw new Error('Wrong zip password')
  const check = createHmac('sha1', keys.subarray(keyLen, keyLen * 2)).update(enc).digest().subarray(0, 10)
  if (!timingSafeEqual(check, mac)) throw new Error('Zip authentication failed')

  // AES-CTR with a little-endian counter starting at 1: build the keystream with ECB.
  const blocks = Math.ceil(enc.length / 16)
  const counters = Buffer.alloc(blocks * 16)
  for (let b = 0; b < blocks; b++) counters.writeUInt32LE(b + 1, b * 16)
  const ecb = createCipheriv(`aes-${keyLen * 8}-ecb`, keys.subarray(0, keyLen), null)
  ecb.setAutoPadding(false)
  const stream = ecb.update(counters)
  const plain = Buffer.alloc(enc.length)
  for (let i = 0; i < enc.length; i++) plain[i] = enc[i] ^ stream[i]
  return { name, data: realMethod === 8 ? inflateRawSync(plain) : plain }
}

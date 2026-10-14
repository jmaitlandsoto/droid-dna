// Downloads the JDK and the JADX bridge JAR on first use and returns the
// environment REA needs. Everything logs to stderr: stdout belongs to MCP.
import { createHash } from 'node:crypto'
import { createReadStream, createWriteStream, existsSync, mkdirSync, renameSync, rmSync, readdirSync } from 'node:fs'
import { pipeline } from 'node:stream/promises'
import { Readable } from 'node:stream'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { TOOLS, JDK_DIR, JADX_JAR } from './paths.mjs'

const JADX_URL = 'https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar'
const JADX_SHA256 = '6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75'
const JDK_MAJOR = 21

const log = (...a) => console.error('[readroid]', ...a)

function platform() {
  const os = { linux: 'linux', darwin: 'mac', win32: 'windows' }[process.platform]
  const arch = { x64: 'x64', arm64: 'aarch64' }[process.arch]
  if (!os || !arch) throw new Error(`Unsupported platform ${process.platform}/${process.arch}`)
  return { os, arch }
}

const javaBin = () => join(JDK_DIR, 'bin', process.platform === 'win32' ? 'java.exe' : 'java')
const javaHome = () => (process.platform === 'darwin' ? join(JDK_DIR, 'Contents', 'Home') : JDK_DIR)

async function sha256(file) {
  const h = createHash('sha256')
  await pipeline(createReadStream(file), h)
  return h.digest('hex')
}

async function download(url, dest, expectedSha) {
  log('downloading', url)
  const res = await fetch(url, { redirect: 'follow' })
  if (!res.ok) throw new Error(`Download failed (${res.status}): ${url}`)
  const tmp = dest + '.part'
  await pipeline(Readable.fromWeb(res.body), createWriteStream(tmp, { mode: 0o600 }))
  const got = await sha256(tmp)
  if (got !== expectedSha) {
    rmSync(tmp, { force: true })
    throw new Error(`Checksum mismatch for ${url}: expected ${expectedSha}, got ${got}`)
  }
  renameSync(tmp, dest)
}

async function ensureJdk() {
  if (existsSync(javaBin()) && existsSync(javaHome())) return
  const { os, arch } = platform()
  const meta = await (await fetch(
    `https://api.adoptium.net/v3/assets/latest/${JDK_MAJOR}/hotspot?architecture=${arch}&image_type=jdk&os=${os}&vendor=eclipse`)).json()
  const pkg = meta?.[0]?.binary?.package
  if (!pkg) throw new Error('Adoptium returned no JDK for this platform')
  mkdirSync(TOOLS, { recursive: true })
  const archive = join(TOOLS, pkg.name)
  await download(pkg.link, archive, pkg.checksum)
  const tmpDir = join(TOOLS, 'jdk.tmp')
  rmSync(tmpDir, { recursive: true, force: true })
  mkdirSync(tmpDir)
  const r = spawnSync('tar', ['-xf', archive, '-C', tmpDir, '--strip-components=1'], { stdio: ['ignore', 'ignore', 'inherit'] })
  if (r.status !== 0) throw new Error('Could not extract the JDK (is `tar` installed?)')
  rmSync(archive, { force: true })
  rmSync(JDK_DIR, { recursive: true, force: true })
  renameSync(tmpDir, JDK_DIR)
  log('JDK ready at', JDK_DIR, readdirSync(JDK_DIR).length ? '' : '(empty?)')
}

async function ensureJar() {
  if (existsSync(JADX_JAR) && (await sha256(JADX_JAR)) === JADX_SHA256) return
  mkdirSync(TOOLS, { recursive: true })
  await download(JADX_URL, JADX_JAR, JADX_SHA256)
}

export async function ensureToolchain() {
  await ensureJdk()
  await ensureJar()
  return {
    JAVA_HOME: javaHome(),
    PATH: join(javaHome(), 'bin') + (process.platform === 'win32' ? ';' : ':') + (process.env.PATH ?? ''),
    REA_JADX_MCP_JAR: JADX_JAR,
  }
}

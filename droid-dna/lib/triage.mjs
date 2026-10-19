// Tier 0 (identity) and tier 1 (static rules). Rules are leads, never verdicts.
import { spawn } from 'node:child_process'
import { ensureToolchain } from './toolchain.mjs'

const REA_VERSION = '6.5.0'

export async function reaInspectPackage(apkPath, timeoutMs = 300000) {
  const env = { ...process.env, ...(await ensureToolchain()) }
  const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx'
  return new Promise((resolve, reject) => {
    const p = spawn(npx, ['-y', `rea-agents@${REA_VERSION}`, 'inspect-android-package', apkPath, '--format', 'json'], { env })
    let out = '', err = ''
    const timer = setTimeout(() => { p.kill(); reject(new Error('REA timed out')) }, timeoutMs)
    p.stdout.on('data', d => (out += d))
    p.stderr.on('data', d => (err += d))
    p.on('error', reject)
    p.on('close', code => {
      clearTimeout(timer)
      if (code !== 0) return reject(new Error(`REA exited ${code}: ${err.slice(0, 500)}`))
      try { resolve(JSON.parse(out)) } catch { reject(new Error('REA output was not JSON')) }
    })
  })
}

const has = (perms, ...names) => names.every(n => perms.has('android.permission.' + n))

function components(xml) {
  const out = []
  const re = /<(activity|activity-alias|service|receiver|provider)\b([^>]*?)(\/>|>([\s\S]*?)<\/\1>)/g
  for (let m; (m = re.exec(xml));) {
    const attrs = m[2], body = m[4] ?? ''
    const attr = k => attrs.match(new RegExp(`android:${k}="([^"]*)"`))?.[1]
    out.push({
      kind: m[1], name: attr('name'), exported: attr('exported'), permission: attr('permission'),
      actions: [...body.matchAll(/<action[^>]*android:name="([^"]*)"/g)].map(x => x[1]),
      hasLauncher: /android\.intent\.category\.LAUNCHER/.test(body),
    })
  }
  return out
}

// id, category, severity, weight, test(ctx) -> evidence string | null
const RULES = [
  { id: 'perm.sms_full', category: 'spyware', severity: 'high', weight: 30,
    title: 'Can read, receive and send SMS',
    test: c => has(c.perms, 'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS') ? 'READ_SMS + RECEIVE_SMS + SEND_SMS' : null },
  { id: 'perm.sms_intercept', category: 'spyware', severity: 'medium', weight: 15,
    title: 'Can intercept incoming SMS',
    test: c => has(c.perms, 'RECEIVE_SMS') && c.perms.has('android.permission.INTERNET') ? 'RECEIVE_SMS + INTERNET' : null },
  { id: 'perm.contacts_rw', category: 'spyware', severity: 'medium', weight: 10,
    title: 'Reads and writes contacts',
    test: c => has(c.perms, 'READ_CONTACTS', 'WRITE_CONTACTS') ? 'READ_CONTACTS + WRITE_CONTACTS' : null },
  { id: 'perm.call_phone', category: 'fraud', severity: 'medium', weight: 10,
    title: 'Can place calls without the dialer',
    test: c => has(c.perms, 'CALL_PHONE') ? 'CALL_PHONE' : null },
  { id: 'perm.overlay', category: 'banker', severity: 'high', weight: 25,
    title: 'Draws over other apps',
    test: c => has(c.perms, 'SYSTEM_ALERT_WINDOW') ? 'SYSTEM_ALERT_WINDOW' : null },
  { id: 'perm.install_packages', category: 'dropper', severity: 'medium', weight: 15,
    title: 'Can install other packages',
    test: c => has(c.perms, 'REQUEST_INSTALL_PACKAGES') ? 'REQUEST_INSTALL_PACKAGES' : null },
  { id: 'perm.battery_whitelist', category: 'persistence', severity: 'low', weight: 5,
    title: 'Asks to be exempt from battery optimization',
    test: c => has(c.perms, 'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS') ? 'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS' : null },
  { id: 'manifest.accessibility', category: 'banker', severity: 'high', weight: 30,
    title: 'Declares an accessibility service',
    test: c => c.components.find(x => x.actions.includes('android.accessibilityservice.AccessibilityService'))?.name ?? null },
  { id: 'manifest.device_admin', category: 'ransomware', severity: 'high', weight: 25,
    title: 'Declares a device admin receiver',
    test: c => c.components.find(x => x.actions.includes('android.app.action.DEVICE_ADMIN_ENABLED'))?.name ?? null },
  { id: 'manifest.boot_receiver', category: 'persistence', severity: 'low', weight: 5,
    title: 'Starts at boot',
    test: c => c.components.find(x => x.actions.includes('android.intent.action.BOOT_COMPLETED'))?.name ?? null },
  { id: 'manifest.sms_receiver', category: 'spyware', severity: 'medium', weight: 15,
    title: 'Registers a receiver for incoming SMS',
    test: c => c.components.find(x => x.actions.includes('android.provider.Telephony.SMS_RECEIVED'))?.name ?? null },
  { id: 'code.tiny_dex', category: 'obfuscation', severity: 'low', weight: 5,
    title: 'Very few classes (possible packer or stub)',
    test: c => (c.classCount ?? 999) < 30 ? `${c.classCount} classes` : null },
]

export function tier1(result, native) {
  const n = result.normalized_result ?? {}
  const perms = new Set(n.permissions ?? [])
  const comps = components(n.manifest?.text ?? '')
  const ctx = { perms, components: comps, classCount: n.class_count }
  const findings = []
  let score = 0
  for (const r of RULES) {
    const ev = r.test(ctx)
    if (!ev) continue
    findings.push({ rule_id: r.id, category: r.category, severity: r.severity, title: r.title, evidence: ev })
    score += r.weight
  }
  for (const { weight, ...f } of native?.findings ?? []) {
    findings.push(f)
    score += weight
  }
  score = Math.min(100, score)
  const threshold = Number(process.env.DROID_DNA_THRESHOLD ?? 30)
  return {
    package: n.package_name, versionName: n.version_name, versionCode: n.version_code,
    minSdk: n.min_sdk, targetSdk: n.target_sdk, classCount: n.class_count,
    permissionCount: perms.size, signatureVerification: n.signature_verification,
    findings, score, threshold,
    escalate: score >= threshold || findings.some(f => f.severity === 'high'),
  }
}

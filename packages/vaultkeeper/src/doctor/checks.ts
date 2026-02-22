/**
 * Individual preflight check functions for each system dependency.
 */

import { execCommand } from '../util/exec.js'
import type { PreflightCheck } from '../types.js'

/**
 * Parse a semver-like version string and return [major, minor, patch].
 * Returns null if unparseable.
 */
function parseVersion(raw: string): [number, number, number] | null {
  const match = /(\d+)\.(\d+)\.(\d+)/.exec(raw)
  if (!match) return null
  const major = parseInt(match[1] ?? '0', 10)
  const minor = parseInt(match[2] ?? '0', 10)
  const patch = parseInt(match[3] ?? '0', 10)
  return [major, minor, patch]
}

/**
 * Returns true if [aMajor, aMinor, aPatch] >= [bMajor, bMinor, bPatch].
 */
function versionGte(
  a: [number, number, number],
  b: [number, number, number],
): boolean {
  if (a[0] !== b[0]) return a[0] > b[0]
  if (a[1] !== b[1]) return a[1] > b[1]
  return a[2] >= b[2]
}

/**
 * Check that openssl is present and >= 1.1.1.
 * @internal
 */
export async function checkOpenssl(): Promise<PreflightCheck> {
  const name = 'openssl'
  try {
    const output = await execCommand('openssl', ['version'])
    const parsed = parseVersion(output)
    if (!parsed) {
      return {
        name,
        status: 'version-unsupported',
        version: output,
        reason: 'Could not parse openssl version',
      }
    }
    if (!versionGte(parsed, [1, 1, 1])) {
      return {
        name,
        status: 'version-unsupported',
        version: output,
        reason: 'openssl >= 1.1.1 is required',
      }
    }
    return { name, status: 'ok', version: output }
  } catch {
    return { name, status: 'missing', reason: 'openssl not found in PATH' }
  }
}

/**
 * Check that bash is present.
 * @internal
 */
export async function checkBash(): Promise<PreflightCheck> {
  const name = 'bash'
  try {
    const output = await execCommand('bash', ['--version'])
    const firstLine = output.split('\n')[0] ?? output
    return { name, status: 'ok', version: firstLine }
  } catch {
    return { name, status: 'missing', reason: 'bash not found in PATH' }
  }
}

/**
 * Check that PowerShell is present (Windows only).
 * @internal
 */
export async function checkPowershell(): Promise<PreflightCheck> {
  const name = 'powershell'
  try {
    const output = await execCommand('powershell', [
      '-Command',
      '$PSVersionTable.PSVersion',
    ])
    const version = output.trim()
    return { name, status: 'ok', version }
  } catch {
    return { name, status: 'missing', reason: 'powershell not found in PATH' }
  }
}

/**
 * Check that macOS security CLI is present (macOS only, for Keychain access).
 * @internal
 */
export async function checkSecurity(): Promise<PreflightCheck> {
  const name = 'security'
  try {
    // `security help` exits with non-zero but writes to stderr; we only need it to exist
    await execCommand('security', ['help'])
    return { name, status: 'ok' }
  } catch (err) {
    // security help exits non-zero intentionally — if we got stderr output, it's present
    const message = err instanceof Error ? err.message : String(err)
    if (message.includes('security')) {
      // The command exists but help exits with a non-zero code
      return { name, status: 'ok' }
    }
    return {
      name,
      status: 'missing',
      reason: 'security command not found in PATH',
    }
  }
}

/**
 * Check that secret-tool is present (Linux only).
 * @internal
 */
export async function checkSecretTool(): Promise<PreflightCheck> {
  const name = 'secret-tool'
  try {
    const output = await execCommand('secret-tool', ['--version'])
    return { name, status: 'ok', version: output.trim() }
  } catch {
    return {
      name,
      status: 'missing',
      reason: 'secret-tool not found in PATH (install libsecret-tools)',
    }
  }
}

/**
 * Check that 1Password CLI (op) is present (optional).
 * @internal
 */
export async function checkOp(): Promise<PreflightCheck> {
  const name = 'op'
  try {
    const output = await execCommand('op', ['--version'])
    return { name, status: 'ok', version: output.trim() }
  } catch {
    return {
      name,
      status: 'missing',
      reason: 'op (1Password CLI) not found in PATH',
    }
  }
}

/**
 * Check that ykman (YubiKey Manager CLI) is present (optional).
 * @internal
 */
export async function checkYkman(): Promise<PreflightCheck> {
  const name = 'ykman'
  try {
    const output = await execCommand('ykman', ['--version'])
    return { name, status: 'ok', version: output.trim() }
  } catch {
    return {
      name,
      status: 'missing',
      reason: 'ykman (YubiKey Manager) not found in PATH',
    }
  }
}

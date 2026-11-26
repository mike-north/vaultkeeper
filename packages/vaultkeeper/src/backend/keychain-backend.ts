/**
 * macOS Keychain backend implementation.
 *
 * @remarks
 * Stores secrets as base64-encoded generic passwords in the macOS Keychain
 * using the `security` CLI tool. Service name format: `vaultkeeper:<id>`.
 */

import { isUtf8 } from 'node:buffer'
import { execCommandFull } from '../util/exec.js'
import { BackendLockedError, ExecError, SecretNotFoundError } from '../errors.js'
import type { ListableBackend } from './types.js'

const ACCOUNT = 'vaultkeeper'
const SERVICE_PREFIX = 'vaultkeeper:'

/** Low byte of errSecItemNotFound in the process exit code. */
const ITEM_NOT_FOUND_EXIT = 44

/** Reserve two bytes for the newline and NUL in security's 4096-byte input buffer. */
const MAX_INTERACTIVE_COMMAND_BYTES = 4094

function checkCommandSize(bytes: number): void {
  if (bytes > MAX_INTERACTIVE_COMMAND_BYTES) {
    throw new ExecError('Keychain write exceeds the security command line limit', 'security')
  }
}

/** Escape quotes and backslashes for security's interactive tokenizer. */
function quoteKeychainArgument(value: string): string {
  return `"${value.replace(/[\\"]/g, '\\$&')}"`
}

/** Decode security's path metadata, preferring its hex bytes over the escaped display. */
function keychainPath(stdout: string): string | undefined {
  const hex = /^keychain: 0x((?:[0-9a-f]{2})+) /i.exec(stdout)?.[1]
  let path = /^keychain: "([^\n\r]+)"\n/.exec(stdout)?.[1]
  if (hex !== undefined) {
    const raw = Buffer.from(hex, 'hex')
    path = isUtf8(raw) ? raw.toString('utf8') : undefined
  }
  if (!path?.startsWith('/') || path.includes('\n') || path.includes('\r') || path.includes('\0')) {
    return undefined
  }
  return path
}

function checkKeychainLocked(stderr: string): void {
  if (stderr.toLowerCase().includes('user interaction is not allowed')) {
    throw new BackendLockedError('macOS Keychain is locked', true)
  }
}

/**
 * macOS Keychain secret backend.
 *
 * @remarks
 * Only available on Darwin (macOS). Uses `security` CLI to store/retrieve
 * generic passwords. Secrets are base64-encoded before storage.
 *
 * @internal
 */
export class KeychainBackend implements ListableBackend {
  readonly type = 'keychain'
  readonly displayName = 'macOS Keychain'

  async isAvailable(): Promise<boolean> {
    if (process.platform !== 'darwin') {
      return false
    }
    try {
      const result = await execCommandFull('security', ['list-keychains'])
      return result.exitCode === 0
    } catch {
      return false
    }
  }

  async store(id: string, secret: string): Promise<void> {
    // security tokenizes this input one line at a time.
    if (id.includes('\n') || id.includes('\r') || id.includes('\0')) {
      throw new ExecError('Keychain store requires an ID without line breaks or NUL', 'security')
    }
    const service = `${SERVICE_PREFIX}${id}`
    const encodedBytes = Math.ceil(Buffer.byteLength(secret) / 3) * 4
    checkCommandSize(Buffer.byteLength(service) + encodedBytes)
    const lookup = await execCommandFull('security', [
      'find-generic-password',
      '-a',
      ACCOUNT,
      '-s',
      service,
    ])
    checkKeychainLocked(lookup.stderr)
    // security can report item-not-found after failing to initialize the search.
    if (
      lookup.stderr.includes('SecKeychainSearchCreateFromAttributes:') ||
      (lookup.exitCode !== 0 && lookup.exitCode !== ITEM_NOT_FOUND_EXIT)
    ) {
      throw new ExecError('Failed to locate the macOS Keychain item', 'security')
    }
    // Scope -U to the owning keychain, including its fallback add. A
    // regular add for a missing item lets Keychain reject concurrent duplicates.
    const target = lookup.exitCode === 0 ? keychainPath(lookup.stdout) : undefined
    if (lookup.exitCode === 0 && target === undefined) {
      throw new ExecError('Failed to identify the keychain containing the item', 'security')
    }
    const updateFlag = target === undefined ? '' : ' -U'
    const keychain = target === undefined ? '' : ` ${quoteKeychainArgument(target)}`
    const prefix = `add-generic-password${updateFlag} -a "${ACCOUNT}" -s ${quoteKeychainArgument(service)} -w "`
    const suffix = `"${keychain}\n`
    checkCommandSize(Buffer.byteLength(prefix) + encodedBytes + Buffer.byteLength(suffix) - 1)
    const raw = Buffer.from(secret, 'utf8')
    let encoded: string
    try {
      encoded = raw.toString('base64')
    } finally {
      raw.fill(0)
    }
    // Even an empty password has an explicit token. Keep the script on
    // stdin and exclude the tool's potentially sensitive output from errors.
    const result = await execCommandFull('security', ['-i'], { stdin: prefix + encoded + suffix })
    checkKeychainLocked(result.stderr)
    if (result.exitCode !== 0 || result.stderr.includes('add-generic-password: returned ')) {
      throw new ExecError('macOS Keychain write failed', 'security')
    }
  }

  async retrieve(id: string): Promise<string> {
    const service = `${SERVICE_PREFIX}${id}`
    const result = await execCommandFull('security', [
      'find-generic-password',
      '-a',
      ACCOUNT,
      '-s',
      service,
      '-w',
    ])
    if (result.exitCode !== 0) {
      throw new SecretNotFoundError(`Secret not found in macOS Keychain: ${id}`)
    }
    const encoded = result.stdout.trim()
    const raw = Buffer.from(encoded, 'base64')
    try {
      return raw.toString('utf8')
    } finally {
      raw.fill(0)
    }
  }

  async delete(id: string): Promise<void> {
    const service = `${SERVICE_PREFIX}${id}`
    const result = await execCommandFull('security', [
      'delete-generic-password',
      '-a',
      ACCOUNT,
      '-s',
      service,
    ])
    if (result.exitCode !== 0) {
      throw new SecretNotFoundError(`Secret not found in macOS Keychain: ${id}`)
    }
  }

  async exists(id: string): Promise<boolean> {
    const service = `${SERVICE_PREFIX}${id}`
    const result = await execCommandFull('security', [
      'find-generic-password',
      '-a',
      ACCOUNT,
      '-s',
      service,
    ])
    return result.exitCode === 0
  }

  async list(): Promise<string[]> {
    const result = await execCommandFull('security', ['dump-keychain'])
    if (result.exitCode !== 0) {
      return []
    }
    const ids: string[] = []
    const servicePattern = /0x00000007 <blob>="vaultkeeper:([^"]+)"/g
    let match: RegExpExecArray | null = servicePattern.exec(result.stdout)
    while (match !== null) {
      const id = match[1]
      if (id !== undefined) {
        ids.push(id)
      }
      match = servicePattern.exec(result.stdout)
    }
    return ids
  }
}

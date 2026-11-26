/**
 * macOS Keychain backend implementation.
 *
 * @remarks
 * Stores secrets as base64-encoded generic passwords in the macOS Keychain
 * using the `security` CLI for lookup and creation, and the native Security
 * framework for update-only replacements. Service name format: `vaultkeeper:<id>`.
 */

import { constants as bufferConstants, isUtf8 } from 'node:buffer'
import { execCommandFull } from '../util/exec.js'
import { BackendLockedError, ExecError, SecretNotFoundError } from '../errors.js'
import { KEYCHAIN_CONFIRM_MISS_SCRIPT } from './keychain-confirm-miss.js'
import { KEYCHAIN_UPDATE_SCRIPT } from './keychain-update.js'
import type { ListableBackend } from './types.js'

const ACCOUNT = 'vaultkeeper'
const SERVICE_PREFIX = 'vaultkeeper:'

/** Low byte of errSecItemNotFound in the process exit code. */
const ITEM_NOT_FOUND_EXIT = 44

/** The system JXA runner loads the Security framework without a bundled binary. */
const KEYCHAIN_BRIDGE = '/usr/bin/osascript'

/** The full OSStatus for a locked keychain that would require user interaction. */
const LOCKED_STATUS = '-25308'

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

/** Encode the shared on-disk representation while wiping the temporary UTF-8 bytes. */
function encodeKeychainValue(secret: string): string {
  const raw = Buffer.from(secret, 'utf8')
  try {
    return raw.toString('base64')
  } finally {
    raw.fill(0)
  }
}

/**
 * macOS Keychain secret backend.
 *
 * @remarks
 * Only available on Darwin (macOS). Stores base64-encoded generic passwords.
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
    // NUL cannot be passed as subprocess metadata. Line breaks are valid for legacy updates.
    if (id.includes('\0')) {
      throw new ExecError('Keychain store requires an ID without NUL', 'security')
    }
    const service = `${SERVICE_PREFIX}${id}`
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
    const encodedBytes = Math.ceil(Buffer.byteLength(secret) / 3) * 4
    if (lookup.exitCode === 0) {
      const target = keychainPath(lookup.stdout)
      if (target === undefined) {
        throw new ExecError('Failed to identify the keychain containing the item', 'security')
      }
      await this.updateExisting(target, service, secret, encodedBytes)
    } else {
      await this.addNew(service, secret, encodedBytes)
    }
  }

  /** Require each searched keychain to be readable and explicitly miss the item. */
  private async confirmMissing(service: string): Promise<void> {
    const result = await execCommandFull(KEYCHAIN_BRIDGE, [
      '-l',
      'JavaScript',
      '-e',
      KEYCHAIN_CONFIRM_MISS_SCRIPT,
      '--',
      service,
      ACCOUNT,
    ])
    const status = result.stdout.trim()
    if (result.exitCode === 0 && status === LOCKED_STATUS) {
      throw new BackendLockedError('macOS Keychain is locked', true)
    }
    if (result.exitCode !== 0 || status !== 'absent') {
      throw new ExecError('Failed to confirm the macOS Keychain item is absent', KEYCHAIN_BRIDGE)
    }
  }

  /** Update only the matching item in the keychain that owned it at lookup time. */
  private async updateExisting(
    target: string,
    service: string,
    secret: string,
    encodedBytes: number,
  ): Promise<void> {
    // Node's encoded string limit is below the native UInt32 payload limit.
    if (encodedBytes > bufferConstants.MAX_STRING_LENGTH) {
      throw new ExecError('macOS Keychain replacement is too large to encode', KEYCHAIN_BRIDGE)
    }
    const result = await execCommandFull(
      KEYCHAIN_BRIDGE,
      [
        '-l',
        'JavaScript',
        '-e',
        KEYCHAIN_UPDATE_SCRIPT,
        '--',
        target,
        service,
        ACCOUNT,
        String(encodedBytes),
      ],
      { stdin: encodeKeychainValue(secret) },
    )
    // The helper returns the full OSStatus on stdout. The process exit status describes the runner.
    const status = result.stdout.trim()
    if (result.exitCode === 0 && status === LOCKED_STATUS) {
      throw new BackendLockedError('macOS Keychain is locked', true)
    }
    if (result.exitCode !== 0 || status !== '0') {
      throw new ExecError('macOS Keychain replacement failed', KEYCHAIN_BRIDGE)
    }
  }

  /** Add a new item after a confirmed miss. The default keychain rejects duplicate creates. */
  private async addNew(service: string, secret: string, encodedBytes: number): Promise<void> {
    // The interactive tokenizer treats each line as a command. Existing updates use argv metadata.
    if (service.includes('\n') || service.includes('\r')) {
      throw new ExecError('Keychain creation requires an ID without line breaks', 'security')
    }
    const prefix = `add-generic-password -a "${ACCOUNT}" -s ${quoteKeychainArgument(service)} -w "`
    const suffix = '"\n'
    checkCommandSize(Buffer.byteLength(prefix) + encodedBytes + Buffer.byteLength(suffix) - 1)
    await this.confirmMissing(service)
    // Even an empty password has an explicit token. Keep the script on
    // stdin and exclude the tool's potentially sensitive output from errors.
    const result = await execCommandFull('security', ['-i'], {
      stdin: `${prefix}${encodeKeychainValue(secret)}${suffix}`,
    })
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

/**
 * YubiKey backend implementation.
 *
 * @remarks
 * Stores secrets protected by a YubiKey using the `ykman` CLI tool.
 * Secrets are encrypted using the YubiKey's OATH TOTP/HOTP module
 * or PIV slot for hardware-backed protection.
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import * as os from 'node:os'
import { execCommand, execCommandFull } from '../util/exec.js'
import { SecretNotFoundError, PluginNotFoundError, DeviceNotPresentError } from '../errors.js'
import type { SecretBackend } from './types.js'

const YKMAN_INSTALL_URL = 'https://developers.yubico.com/yubikey-manager/'
const STORAGE_DIR_NAME = path.join('.vaultkeeper', 'yubikey')
const METADATA_FILE = 'metadata.json'
const DEVICE_TIMEOUT_MS = 5000

interface YubikeyMetadata {
  entries: Record<string, string>
}

function getStorageDir(): string {
  return path.join(os.homedir(), STORAGE_DIR_NAME)
}

function getEntryPath(storageDir: string, id: string): string {
  const safeId = Buffer.from(id, 'utf8').toString('hex')
  return path.join(storageDir, `${safeId}.enc`)
}

function isStringRecord(value: unknown): value is Record<string, string> {
  if (value === null || typeof value !== 'object') {
    return false
  }
  return Object.values(value).every((v) => typeof v === 'string')
}

async function loadMetadata(storageDir: string): Promise<YubikeyMetadata> {
  const metaPath = path.join(storageDir, METADATA_FILE)
  try {
    const raw = await fs.readFile(metaPath, 'utf8')
    const parsed: unknown = JSON.parse(raw)
    if (
      parsed !== null &&
      typeof parsed === 'object' &&
      'entries' in parsed &&
      isStringRecord(parsed.entries)
    ) {
      return { entries: parsed.entries }
    }
    return { entries: {} }
  } catch {
    return { entries: {} }
  }
}

async function saveMetadata(storageDir: string, metadata: YubikeyMetadata): Promise<void> {
  const metaPath = path.join(storageDir, METADATA_FILE)
  await fs.writeFile(metaPath, JSON.stringify(metadata, null, 2), { mode: 0o600 })
}

/**
 * YubiKey backend via `ykman` CLI.
 *
 * @remarks
 * Requires ykman to be installed and a YubiKey to be connected.
 * Secrets are stored in files encrypted using the YubiKey's challenge-response
 * capability (HMAC-SHA1) via slot 2.
 *
 * @internal
 */
export class YubikeyBackend implements SecretBackend {
  readonly type = 'yubikey'
  readonly displayName = 'YubiKey'

  async isAvailable(): Promise<boolean> {
    try {
      const result = await execCommandFull('ykman', ['--version'])
      if (result.exitCode !== 0) {
        return false
      }
      // Also verify a YubiKey is connected
      const listResult = await execCommandFull('ykman', ['list'])
      return listResult.exitCode === 0 && listResult.stdout.trim() !== ''
    } catch {
      return false
    }
  }

  private async requireDevice(): Promise<void> {
    const available = await this.isAvailable()
    if (!available) {
      const hasYkman = await execCommandFull('ykman', ['--version']).then(
        (r) => r.exitCode === 0,
        () => false,
      )
      if (!hasYkman) {
        throw new PluginNotFoundError('ykman is not installed', 'ykman', YKMAN_INSTALL_URL)
      }
      throw new DeviceNotPresentError('No YubiKey device detected', DEVICE_TIMEOUT_MS)
    }
  }

  async store(id: string, secret: string): Promise<void> {
    await this.requireDevice()

    const storageDir = getStorageDir()
    await fs.mkdir(storageDir, { recursive: true, mode: 0o700 })

    // Use ykman's OATH module to store a TOTP entry as the challenge key,
    // and store the actual secret encrypted with challenge-response in a file.
    // For a pragmatic implementation: use challenge-response slot 2 to derive
    // a key, then encrypt the secret with openssl using that key.
    const challenge = Buffer.from(`vaultkeeper:${id}`, 'utf8').toString('hex')
    const responseResult = await execCommandFull('ykman', [
      'otp',
      'calculate',
      '2',
      challenge,
    ])

    if (responseResult.exitCode !== 0) {
      throw new Error(`YubiKey challenge-response failed: ${responseResult.stderr}`)
    }

    const derivedKey = responseResult.stdout.trim()
    const entryPath = getEntryPath(storageDir, id)

    // Pass the derived key via stdin to avoid exposing it in the process table.
    // Input to openssl enc is read from stdin when -pass stdin is used;
    // we prepend the passphrase line followed by the secret via a two-pass approach.
    // openssl -pass stdin reads the first line as the passphrase and the rest as data.
    await execCommand(
      'openssl',
      ['enc', '-aes-256-cbc', '-pbkdf2', '-pass', 'stdin', '-out', entryPath],
      { stdin: `${derivedKey}\n${secret}` },
    )

    const metadata = await loadMetadata(storageDir)
    metadata.entries[id] = entryPath
    await saveMetadata(storageDir, metadata)
  }

  async retrieve(id: string): Promise<string> {
    await this.requireDevice()

    const storageDir = getStorageDir()
    const entryPath = getEntryPath(storageDir, id)

    try {
      await fs.access(entryPath)
    } catch {
      throw new SecretNotFoundError(`Secret not found in YubiKey store: ${id}`)
    }

    const challenge = Buffer.from(`vaultkeeper:${id}`, 'utf8').toString('hex')
    const responseResult = await execCommandFull('ykman', [
      'otp',
      'calculate',
      '2',
      challenge,
    ])

    if (responseResult.exitCode !== 0) {
      throw new Error(`YubiKey challenge-response failed: ${responseResult.stderr}`)
    }

    const derivedKey = responseResult.stdout.trim()

    // Pass the derived key via stdin to avoid exposing it in the process table.
    const result = await execCommandFull('openssl', [
      'enc',
      '-d',
      '-aes-256-cbc',
      '-pbkdf2',
      '-pass',
      'stdin',
      '-in',
      entryPath,
    ], { stdin: `${derivedKey}\n` })

    if (result.exitCode !== 0) {
      throw new Error(`Failed to decrypt YubiKey-protected secret: ${result.stderr}`)
    }

    return result.stdout
  }

  async delete(id: string): Promise<void> {
    await this.requireDevice()

    const storageDir = getStorageDir()
    const entryPath = getEntryPath(storageDir, id)

    try {
      await fs.unlink(entryPath)
    } catch (err) {
      if (err instanceof Error && 'code' in err && err.code === 'ENOENT') {
        throw new SecretNotFoundError(`Secret not found in YubiKey store: ${id}`)
      }
      throw err
    }

    const metadata = await loadMetadata(storageDir)
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete metadata.entries[id]
    await saveMetadata(storageDir, metadata)
  }

  async exists(id: string): Promise<boolean> {
    const storageDir = getStorageDir()
    const entryPath = getEntryPath(storageDir, id)

    try {
      await fs.access(entryPath)
      return true
    } catch {
      return false
    }
  }
}

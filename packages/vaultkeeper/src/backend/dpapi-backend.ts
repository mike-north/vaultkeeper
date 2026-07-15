/**
 * Windows DPAPI backend implementation.
 *
 * @remarks
 * Stores secrets using Windows Data Protection API (DPAPI) via PowerShell.
 * DPAPI encrypts data using the current user's credentials and machine key.
 */

import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import * as os from 'node:os'
import { execCommand, execCommandFull } from '../util/exec.js'
import { SecretNotFoundError, toFilesystemError } from '../errors.js'
import type { ListableBackend } from './types.js'

/**
 * Resolve the storage directory for a DpapiBackend instance.
 *
 * When `configuredPath` is provided (from `BackendConfig.path`), encrypted
 * blobs are stored directly under that directory. Otherwise the default
 * `$HOME/.vaultkeeper/dpapi` location is used.
 */
function resolveStorageDir(configuredPath?: string): string {
  // Config validation (see validateConfig) rejects empty/whitespace-only
  // paths, so any defined value here is guaranteed non-blank.
  if (configuredPath !== undefined) {
    return configuredPath
  }
  return path.join(os.homedir(), '.vaultkeeper', 'dpapi')
}

function getEntryPath(storageDir: string, id: string): string {
  // Use hex encoding of id for safe filenames
  const safeId = Buffer.from(id, 'utf8').toString('hex')
  return path.join(storageDir, `${safeId}.enc`)
}

/**
 * Windows DPAPI secret backend.
 *
 * @remarks
 * Only available on Windows. Uses PowerShell with
 * [System.Security.Cryptography.ProtectedData] to encrypt/decrypt secrets.
 * Encrypted blobs are stored in ~/.vaultkeeper/dpapi/.
 *
 * @internal
 */
export class DpapiBackend implements ListableBackend {
  readonly type = 'dpapi'
  readonly displayName = 'Windows DPAPI'

  readonly #storageDir: string

  /**
   * @param storageDir - Directory in which encrypted blobs are stored.
   *   Sourced from `BackendConfig.path`. Defaults to `$HOME/.vaultkeeper/dpapi`.
   */
  constructor(storageDir?: string) {
    this.#storageDir = resolveStorageDir(storageDir)
  }

  async isAvailable(): Promise<boolean> {
    if (process.platform !== 'win32') {
      return false
    }
    try {
      const result = await execCommandFull('powershell', [
        '-NoProfile',
        '-Command',
        '[System.Security.Cryptography.ProtectedData] | Out-Null; exit 0',
      ])
      return result.exitCode === 0
    } catch {
      return false
    }
  }

  async store(id: string, secret: string): Promise<void> {
    const storageDir = this.#storageDir
    await fs.mkdir(storageDir, { recursive: true })
    const entryPath = getEntryPath(storageDir, id)

    const script = [
      'Add-Type -AssemblyName System.Security',
      `$bytes = [System.Text.Encoding]::UTF8.GetBytes(${JSON.stringify(secret)})`,
      '$entropy = $null',
      '$scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser',
      '$encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, $scope)',
      `[System.IO.File]::WriteAllBytes(${JSON.stringify(entryPath)}, $encrypted)`,
    ].join('; ')

    await execCommand('powershell', ['-NoProfile', '-Command', script])
  }

  async retrieve(id: string): Promise<string> {
    const storageDir = this.#storageDir
    const entryPath = getEntryPath(storageDir, id)

    try {
      await fs.access(entryPath)
    } catch {
      throw new SecretNotFoundError(`Secret not found in Windows DPAPI store: ${id}`)
    }

    const script = [
      'Add-Type -AssemblyName System.Security',
      `$encrypted = [System.IO.File]::ReadAllBytes(${JSON.stringify(entryPath)})`,
      '$entropy = $null',
      '$scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser',
      '$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $entropy, $scope)',
      'Write-Output ([System.Text.Encoding]::UTF8.GetString($bytes))',
    ].join('; ')

    return execCommand('powershell', ['-NoProfile', '-Command', script])
  }

  async delete(id: string): Promise<void> {
    const storageDir = this.#storageDir
    const entryPath = getEntryPath(storageDir, id)

    try {
      await fs.unlink(entryPath)
    } catch (err) {
      if (err instanceof Error && 'code' in err && err.code === 'ENOENT') {
        throw new SecretNotFoundError(`Secret not found in Windows DPAPI store: ${id}`)
      }
      // Same contract as FileBackend.delete (#126): a non-ENOENT unlink
      // failure surfaces as a typed FilesystemError, never a raw Node error.
      throw toFilesystemError(err, 'secret file', entryPath, 'delete')
    }
  }

  async exists(id: string): Promise<boolean> {
    const storageDir = this.#storageDir
    const entryPath = getEntryPath(storageDir, id)

    try {
      await fs.access(entryPath)
      return true
    } catch {
      return false
    }
  }

  async list(): Promise<string[]> {
    const storageDir = this.#storageDir
    let entries: string[]
    try {
      entries = await fs.readdir(storageDir)
    } catch {
      return []
    }
    return entries
      .filter((f) => f.endsWith('.enc'))
      .map((f) => Buffer.from(f.slice(0, -4), 'hex').toString('utf8'))
  }
}

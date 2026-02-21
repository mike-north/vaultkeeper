/**
 * macOS Keychain backend implementation.
 *
 * @remarks
 * Stores secrets as base64-encoded generic passwords in the macOS Keychain
 * using the `security` CLI tool. Service name format: `vaultkeeper:<id>`.
 *
 * @packageDocumentation
 */

import { execCommand, execCommandFull } from '../util/exec.js'
import { SecretNotFoundError } from '../errors.js'
import type { SecretBackend } from './types.js'

const ACCOUNT = 'vaultkeeper'
const SERVICE_PREFIX = 'vaultkeeper:'

/**
 * macOS Keychain secret backend.
 *
 * @remarks
 * Only available on Darwin (macOS). Uses `security` CLI to store/retrieve
 * generic passwords. Secrets are base64-encoded before storage.
 *
 * @public
 */
export class KeychainBackend implements SecretBackend {
  readonly type = 'keychain'
  readonly displayName = 'macOS Keychain'

  async isAvailable(): Promise<boolean> {
    if (process.platform !== 'darwin') {
      return false
    }
    try {
      const result = await execCommandFull('security', ['version'])
      return result.exitCode === 0
    } catch {
      return false
    }
  }

  async store(id: string, secret: string): Promise<void> {
    const service = `${SERVICE_PREFIX}${id}`
    const encoded = Buffer.from(secret, 'utf8').toString('base64')
    // Delete existing entry first (ignore errors) then add fresh
    await execCommandFull('security', [
      'delete-generic-password',
      '-a',
      ACCOUNT,
      '-s',
      service,
    ])
    await execCommand('security', [
      'add-generic-password',
      '-a',
      ACCOUNT,
      '-s',
      service,
      '-w',
      encoded,
    ])
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
    return Buffer.from(encoded, 'base64').toString('utf8')
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
}

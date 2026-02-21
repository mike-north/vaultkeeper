/**
 * 1Password backend implementation.
 *
 * @remarks
 * Stores secrets in 1Password using the `op` CLI tool.
 * Each secret is stored as a "Password" item in the specified vault.
 *
 * @packageDocumentation
 */

import { execCommand, execCommandFull } from '../util/exec.js'
import { SecretNotFoundError, PluginNotFoundError } from '../errors.js'
import type { SecretBackend } from './types.js'

const ITEM_CATEGORY = 'Password'
const TAG = 'vaultkeeper'
const OP_INSTALL_URL = 'https://1password.com/downloads/command-line/'

/**
 * 1Password backend via `op` CLI.
 *
 * @remarks
 * Requires the 1Password CLI (`op`) to be installed and authenticated.
 * Secrets are stored as Password items in the default vault or a configured vault.
 *
 * @public
 */
export class OnePasswordBackend implements SecretBackend {
  readonly type = '1password'
  readonly displayName = '1Password'

  private readonly vault?: string

  constructor(vault?: string) {
    if (vault !== undefined) {
      this.vault = vault
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      const result = await execCommandFull('op', ['--version'])
      return result.exitCode === 0
    } catch {
      return false
    }
  }

  private vaultArgs(): string[] {
    if (this.vault !== undefined) {
      return ['--vault', this.vault]
    }
    return []
  }

  async store(id: string, secret: string): Promise<void> {
    if (!(await this.isAvailable())) {
      throw new PluginNotFoundError(
        '1Password CLI (op) is not available',
        'op',
        OP_INSTALL_URL,
      )
    }

    // Check if item already exists
    const alreadyExists = await this.exists(id)

    if (alreadyExists) {
      // Edit existing item
      await execCommand('op', [
        'item',
        'edit',
        id,
        `password=${secret}`,
        ...this.vaultArgs(),
      ])
    } else {
      // Create new item
      await execCommand('op', [
        'item',
        'create',
        '--category',
        ITEM_CATEGORY,
        '--title',
        id,
        `password=${secret}`,
        '--tags',
        TAG,
        ...this.vaultArgs(),
      ])
    }
  }

  async retrieve(id: string): Promise<string> {
    if (!(await this.isAvailable())) {
      throw new PluginNotFoundError(
        '1Password CLI (op) is not available',
        'op',
        OP_INSTALL_URL,
      )
    }

    const result = await execCommandFull('op', [
      'item',
      'get',
      id,
      '--fields',
      'password',
      ...this.vaultArgs(),
    ])

    if (result.exitCode !== 0) {
      throw new SecretNotFoundError(`Secret not found in 1Password: ${id}`)
    }

    return result.stdout.trim()
  }

  async delete(id: string): Promise<void> {
    if (!(await this.isAvailable())) {
      throw new PluginNotFoundError(
        '1Password CLI (op) is not available',
        'op',
        OP_INSTALL_URL,
      )
    }

    const result = await execCommandFull('op', [
      'item',
      'delete',
      id,
      ...this.vaultArgs(),
    ])

    if (result.exitCode !== 0) {
      throw new SecretNotFoundError(`Secret not found in 1Password: ${id}`)
    }
  }

  async exists(id: string): Promise<boolean> {
    if (!(await this.isAvailable())) {
      return false
    }

    const result = await execCommandFull('op', [
      'item',
      'get',
      id,
      '--fields',
      'title',
      ...this.vaultArgs(),
    ])

    return result.exitCode === 0
  }
}

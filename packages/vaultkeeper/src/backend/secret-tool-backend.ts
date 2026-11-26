/**
 * Linux secret-tool backend implementation.
 *
 * @remarks
 * Stores secrets using the `secret-tool` CLI which interfaces with the
 * GNOME Keyring or any other Secret Service API implementation via D-Bus.
 */

import { execCommand, execCommandFull } from '../util/exec.js'
import { SecretNotFoundError } from '../errors.js'
import type { ListableBackend } from './types.js'

const ATTRIBUTE_KEY = 'vaultkeeper-id'
const LABEL_PREFIX = 'vaultkeeper: '

/**
 * Strip exactly one trailing `\n` from `secret-tool lookup` output, if
 * present — not a full `.trim()`.
 *
 * @remarks
 * `secret-tool lookup` prints the stored secret followed by a single
 * trailing newline that it adds itself; that newline is not part of the
 * secret and must be removed. A full `.trim()` would also strip legitimate
 * leading/trailing whitespace that is part of the secret value itself (a
 * secret may intentionally be or contain whitespace), so only the one
 * newline `secret-tool` appends is removed here.
 */
function stripSecretToolTrailingNewline(stdout: string): string {
  return stdout.endsWith('\n') ? stdout.slice(0, -1) : stdout
}

/**
 * Linux secret-tool (Secret Service API) backend.
 *
 * @remarks
 * Only available on Linux with secret-tool installed. Requires a running
 * Secret Service (e.g., GNOME Keyring or KWallet with Secret Service plugin).
 *
 * @internal
 */
export class SecretToolBackend implements ListableBackend {
  readonly type = 'secret-tool'
  readonly displayName = 'Linux Secret Service (secret-tool)'

  async isAvailable(): Promise<boolean> {
    if (process.platform !== 'linux') {
      return false
    }
    try {
      const result = await execCommandFull('secret-tool', ['--version'])
      return result.exitCode === 0
    } catch {
      return false
    }
  }

  async store(id: string, secret: string): Promise<void> {
    const label = `${LABEL_PREFIX}${id}`
    // The `--` separator stops secret-tool's own GOption argv parser from
    // treating a hostile id (e.g. `--label`, `--foo`, or any leading-dash
    // value) as a flag — everything after `--` is forced positional. Only
    // ATTRIBUTE_KEY and id are positional here; `--label`'s value is safe
    // regardless of content because GOption binds it to the option itself.
    await execCommand('secret-tool', ['store', '--label', label, '--', ATTRIBUTE_KEY, id], {
      stdin: secret,
    })
  }

  async retrieve(id: string): Promise<string> {
    const result = await execCommandFull('secret-tool', ['lookup', '--', ATTRIBUTE_KEY, id])
    // Not-found is determined solely by exit code — never by whether the
    // trimmed stdout is empty. A stored secret may legitimately be an empty
    // string or whitespace-only, and both trim to '', which would otherwise
    // be indistinguishable from "no such entry" (see issue #297).
    if (result.exitCode !== 0) {
      throw new SecretNotFoundError(`Secret not found in Secret Service: ${id}`)
    }
    return stripSecretToolTrailingNewline(result.stdout)
  }

  async delete(id: string): Promise<void> {
    const result = await execCommandFull('secret-tool', ['clear', '--', ATTRIBUTE_KEY, id])
    if (result.exitCode !== 0) {
      throw new SecretNotFoundError(`Secret not found in Secret Service: ${id}`)
    }
  }

  async exists(id: string): Promise<boolean> {
    const result = await execCommandFull('secret-tool', ['lookup', '--', ATTRIBUTE_KEY, id])
    return result.exitCode === 0
  }

  async list(): Promise<string[]> {
    const result = await execCommandFull('secret-tool', ['search', '--', ATTRIBUTE_KEY, ''])
    if (result.exitCode !== 0) {
      return []
    }
    const ids: string[] = []
    const attrPattern = new RegExp(`attribute\\.${ATTRIBUTE_KEY} = (.+)`, 'g')
    let match: RegExpExecArray | null = attrPattern.exec(result.stdout)
    while (match !== null) {
      const id = match[1]
      if (id !== undefined) {
        ids.push(id)
      }
      match = attrPattern.exec(result.stdout)
    }
    return ids
  }
}

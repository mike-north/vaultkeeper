/**
 * Side-effect module that registers all built-in backends with the {@link BackendRegistry}.
 *
 * @remarks
 * Imported from the package entry point (`index.ts`) so that built-in backends
 * are available immediately after `import 'vaultkeeper'`.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/21
 */

import type { BackendConfig } from '../types.js'
import { BackendRegistry } from './registry.js'
import { FileBackend } from './file-backend.js'
import { KeychainBackend } from './keychain-backend.js'
import { DpapiBackend } from './dpapi-backend.js'
import { SecretToolBackend } from './secret-tool-backend.js'
import { OnePasswordBackend } from './one-password-backend.js'
import type { OnePasswordBackendOptions } from './one-password-backend.js'
import { YubikeyBackend } from './yubikey-backend.js'

/**
 * Register all built-in backends with the {@link BackendRegistry}.
 *
 * @remarks
 * Called automatically as a module side-effect. Also exported so that tests
 * can re-register builtins after calling `BackendRegistry.clearBackends()`.
 *
 * @internal
 */
export function registerBuiltinBackends(): void {
  BackendRegistry.register('file', () => new FileBackend())
  BackendRegistry.register('keychain', () => new KeychainBackend())
  BackendRegistry.register('dpapi', () => new DpapiBackend())
  BackendRegistry.register('secret-tool', () => new SecretToolBackend())
  BackendRegistry.register('1password', (config?: BackendConfig) => {
    const opts = config?.options
    const vaultId = opts?.vaultId ?? ''
    const opOptions: OnePasswordBackendOptions = {
      vault: vaultId,
      // 'session' is the safer default — 'per-access' re-prompts on every read.
      accessMode: opts?.accessMode === 'per-access' ? 'per-access' : 'session',
    }
    const account = opts?.account
    if (account !== undefined) {
      opOptions.account = account
    }
    const serviceAccountToken = opts?.serviceAccountToken
    if (serviceAccountToken !== undefined) {
      opOptions.serviceAccountToken = serviceAccountToken
    }
    return new OnePasswordBackend(opOptions)
  })
  BackendRegistry.register('yubikey', () => new YubikeyBackend())
}

registerBuiltinBackends()

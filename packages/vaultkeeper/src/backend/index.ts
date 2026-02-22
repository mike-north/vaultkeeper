/**
 * Backend abstraction layer barrel export.
 */

export type { SecretBackend, BackendFactory, ListableBackend } from './types.js'
export { isListableBackend } from './types.js'
export { BackendRegistry } from './registry.js'
export { KeychainBackend } from './keychain-backend.js'
export { DpapiBackend } from './dpapi-backend.js'
export { SecretToolBackend } from './secret-tool-backend.js'
export { FileBackend } from './file-backend.js'
export { OnePasswordBackend } from './one-password-backend.js'
export { YubikeyBackend } from './yubikey-backend.js'

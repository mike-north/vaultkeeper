/**
 * vaultkeeper — Unified, policy-enforced secret storage across OS backends.
 *
 * @packageDocumentation
 */

export {
  VaultError,
  BackendLockedError,
  DeviceNotPresentError,
  AuthorizationDeniedError,
  BackendUnavailableError,
  PluginNotFoundError,
  SecretNotFoundError,
  TokenExpiredError,
  KeyRotatedError,
  KeyRevokedError,
  TokenRevokedError,
  UsageLimitExceededError,
  IdentityMismatchError,
  SetupError,
  FilesystemError,
  RotationInProgressError,
} from './errors.js'

export type {
  TrustTier,
  KeyStatus,
  PreflightCheckStatus,
  PreflightCheck,
  PreflightResult,
  VaultResponse,
  FetchRequest,
  ExecRequest,
  ExecResult,
  SecretAccessor,
  SignRequest,
  SignResult,
  VerifyRequest,
  VaultConfig,
  BackendConfig,
} from './types.js'

export type { SecretBackend, BackendFactory, ListableBackend } from './backend/index.js'
export { BackendRegistry, isListableBackend } from './backend/index.js'

export { CapabilityToken } from './identity/index.js'

export { VaultKeeper } from './vault.js'
export type { VaultKeeperOptions, SetupOptions } from './vault.js'

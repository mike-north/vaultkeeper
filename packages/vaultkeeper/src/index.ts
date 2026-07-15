/**
 * vaultkeeper — Unified, policy-enforced secret storage across OS backends.
 *
 * @packageDocumentation
 */

// Side-effect: register all built-in backends with BackendRegistry
import './backend/register-builtins.js'

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
  ExecutableTrustRequiredError,
  ExecError,
  InvalidTokenError,
  AccessorConsumedError,
  InvalidAlgorithmError,
  InvalidKeyMaterialError,
  SigningKeyNotFoundError,
  SigningKeyAlreadyExistsError,
  SigningNotSupportedError,
  DecryptionError,
  FetchError,
  SetupError,
  FilesystemError,
  RotationInProgressError,
  ConfigValidationError,
  ConfigParseError,
} from './errors.js'

export type {
  TrustTier,
  KeyStatus,
  PreflightCheckStatus,
  PreflightCheckErrorKind,
  PreflightCheckError,
  PreflightCheck,
  ScopedPreflightCheck,
  PreflightResult,
  VaultResponse,
  FetchRequest,
  ExecRequest,
  ExecResult,
  SecretAccessor,
  SignRequest,
  SignResult,
  VerifyRequest,
  SigningAlgorithm,
  SigningPublicKey,
  VaultConfig,
  BackendConfig,
} from './types.js'

export type {
  SecretBackend,
  BackendFactory,
  ListableBackend,
  SigningBackend,
} from './backend/index.js'
export type {
  SetupQuestion,
  SetupChoice,
  SetupResult,
  BackendSetupFactory,
} from './backend/index.js'
export { BackendRegistry, isListableBackend, isSigningBackend } from './backend/index.js'

export { CapabilityToken } from './identity/index.js'

export { VaultKeeper } from './vault.js'
export type {
  VaultKeeperOptions,
  SetupOptions,
  SetupOptionsBase,
  SecretTokenMap,
  ExecutableTrustStatus,
} from './vault.js'

export { redactSecrets, REDACTED } from './access/index.js'

export { defaultBackendType, platformNativeBackendType } from './config.js'
export { getDefaultConfigDir, getPlatformDefaultConfigDir, loadConfig } from './config.js'

export { runDoctor } from './doctor/runner.js'
export type { RunDoctorOptions } from './doctor/runner.js'
export type { Platform } from './util/platform.js'

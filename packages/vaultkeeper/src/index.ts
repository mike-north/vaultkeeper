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
  VaultClaims,
  VaultResponse,
  FetchRequest,
  ExecRequest,
  ExecResult,
  SecretAccessor,
  VaultConfig,
  BackendConfig,
} from './types.js'

export type { SecretBackend, BackendFactory } from './backend/index.js'
export {
  BackendRegistry,
  KeychainBackend,
  DpapiBackend,
  SecretToolBackend,
  FileBackend,
  OnePasswordBackend,
  YubikeyBackend,
} from './backend/index.js'

export {
  createToken,
  decryptToken,
  extractKid,
  validateClaims,
  blockToken,
  isBlocked,
  clearBlocklist,
} from './jwe/index.js'
export type { CreateTokenOptions, VaultJWEHeader } from './jwe/index.js'

export { KeyManager } from './keys/index.js'
export type { KeyMaterial, KeyState, KeyRotationConfig } from './keys/index.js'

export { delegatedFetch, delegatedExec, createSecretAccessor } from './access/index.js'
export type {
  DelegatedFetchResult,
  DelegatedExecResult,
} from './access/index.js'

export type {
  IdentityInfo,
  TrustVerificationResult,
  TrustOptions,
  TrustManifestEntry,
  TrustManifest,
} from './identity/index.js'
export { hashExecutable, loadManifest, saveManifest, addTrustedHash, isTrusted, verifyTrust } from './identity/index.js'
export { CapabilityToken, createCapabilityToken, validateCapabilityToken } from './identity/index.js'

export { runDoctor } from './doctor/index.js'
export type { RunDoctorOptions, DoctorCheckFn } from './doctor/index.js'
export {
  checkOpenssl,
  checkBash,
  checkPowershell,
  checkSecurity,
  checkSecretTool,
  checkOp,
  checkYkman,
} from './doctor/index.js'

export type { Platform } from './util/platform.js'

export { VaultKeeper } from './vault.js'
export type { VaultKeeperOptions, SetupOptions } from './vault.js'

export { loadConfig, getDefaultConfigDir, validateConfig } from './config.js'

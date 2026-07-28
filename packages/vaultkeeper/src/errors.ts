/**
 * Error hierarchy for vaultkeeper.
 */

/** Base error for all vaultkeeper errors. */
export class VaultError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VaultError'
  }
}

// --- Backend Access Failures ---

/**
 * Thrown when the backend keychain or credential store is locked and requires
 * user interaction (e.g. biometric prompt or password entry) before access can
 * be granted.
 */
export class BackendLockedError extends VaultError {
  /**
   * Whether the lock can be resolved through an interactive user prompt.
   * When `true`, callers may retry after prompting the user.
   */
  readonly interactive: boolean

  constructor(message: string, interactive: boolean) {
    super(message)
    this.name = 'BackendLockedError'
    this.interactive = interactive
  }
}

/**
 * Thrown when a hardware device (e.g. YubiKey or smart card) required for
 * authentication is not currently connected.
 */
export class DeviceNotPresentError extends VaultError {
  /**
   * How long (in milliseconds) the operation waited for the device before
   * giving up.
   */
  readonly timeoutMs: number

  constructor(message: string, timeoutMs: number) {
    super(message)
    this.name = 'DeviceNotPresentError'
    this.timeoutMs = timeoutMs
  }
}

/**
 * Thrown when the user explicitly denies an authorization request for a
 * secret access operation (e.g. cancels an OS permission dialog).
 */
export class AuthorizationDeniedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'AuthorizationDeniedError'
  }
}

/**
 * Thrown when an operation requires a backend capability (e.g.
 * presence-per-use) that the active backend cannot provide.
 *
 * @remarks
 * This is a configuration/backend mismatch, not a runtime authorization
 * failure: the requirement was asserted against a backend whose configured
 * instance does not advertise the capability, so no credential, session, or
 * device is ever touched before this is thrown. It is fixable by switching to
 * (or reconfiguring) a backend that provides the capability — inspect
 * {@link NotCapableError.capability} for which one was required and
 * {@link NotCapableError.backendType} for the backend that lacked it. Distinct
 * from {@link AuthorizationDeniedError} (a human/token rejection) and
 * {@link PresenceDeclinedError} (a human declined a fresh action).
 *
 * @public
 */
export class NotCapableError extends VaultError {
  /** The `type` identifier of the active backend that lacked the capability. */
  readonly backendType: string

  /**
   * The machine-readable capability key that was required but not advertised
   * (e.g. `'presencePerUse'`).
   */
  readonly capability: string

  constructor(message: string, backendType: string, capability: string) {
    super(message)
    this.name = 'NotCapableError'
    this.backendType = backendType
    this.capability = capability
  }
}

/**
 * Thrown when a required fresh, per-use human presence action was explicitly
 * declined by the human (e.g. a biometric or touch prompt was cancelled).
 *
 * @remarks
 * Distinct from {@link AuthorizationDeniedError}, which signals a token or
 * capability rejection, and from {@link PresenceTimeoutError}, which signals the
 * device was present but no action happened in time. A declined presence action
 * means the human was asked and said no.
 *
 * @public
 */
export class PresenceDeclinedError extends VaultError {
  /** The `type` identifier of the backend that requested the presence action. */
  readonly backendType: string

  constructor(message: string, backendType: string) {
    super(message)
    this.name = 'PresenceDeclinedError'
    this.backendType = backendType
  }
}

/**
 * Thrown when a required fresh, per-use human presence action did not happen
 * within the allotted time — the device was present and ready, but no touch,
 * tap, or biometric approval was performed before the timeout elapsed.
 *
 * @remarks
 * Distinct from {@link DeviceNotPresentError} (the device itself was absent) and
 * from {@link PresenceDeclinedError} (the human actively declined). Inspect
 * {@link PresenceTimeoutError.timeoutMs} for how long the operation waited.
 *
 * @public
 */
export class PresenceTimeoutError extends VaultError {
  /** The `type` identifier of the backend that requested the presence action. */
  readonly backendType: string

  /** How long (in milliseconds) the operation waited for the presence action. */
  readonly timeoutMs: number

  constructor(message: string, backendType: string, timeoutMs: number) {
    super(message)
    this.name = 'PresenceTimeoutError'
    this.backendType = backendType
    this.timeoutMs = timeoutMs
  }
}

/**
 * Thrown when no configured backend is available or reachable.
 * Inspect `reason` for a machine-readable cause and `attempted` for the list
 * of backend types that were tried.
 */
export class BackendUnavailableError extends VaultError {
  /**
   * Machine-readable reason code describing why the backend is unavailable
   * (e.g. `'none-enabled'`, `'all-failed'`).
   */
  readonly reason: string

  /**
   * The backend type identifiers that were attempted before this error was
   * thrown.
   */
  readonly attempted: string[]

  constructor(message: string, reason: string, attempted: string[]) {
    super(message)
    this.name = 'BackendUnavailableError'
    this.reason = reason
    this.attempted = attempted
  }
}

/**
 * Thrown when a required backend plugin (e.g. a third-party credential
 * manager) is not installed on the current system.
 */
export class PluginNotFoundError extends VaultError {
  /**
   * The plugin package or binary name that was not found.
   */
  readonly plugin: string

  /**
   * A URL pointing to installation instructions for the missing plugin.
   */
  readonly installUrl: string

  constructor(message: string, plugin: string, installUrl: string) {
    super(message)
    this.name = 'PluginNotFoundError'
    this.plugin = plugin
    this.installUrl = installUrl
  }
}

/**
 * Thrown when a requested secret does not exist in the backend store.
 */
export class SecretNotFoundError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'SecretNotFoundError'
  }
}

// --- JWE Lifecycle Failures ---

/**
 * Thrown when a JWE token has passed its expiration time (`exp` claim).
 */
export class TokenExpiredError extends VaultError {
  /**
   * Whether the token can be refreshed by calling `setup()` again.
   * When `true`, the secret still exists in the backend and a new token can be
   * issued.
   */
  readonly canRefresh: boolean

  constructor(message: string, canRefresh: boolean) {
    super(message)
    this.name = 'TokenExpiredError'
    this.canRefresh = canRefresh
  }
}

/**
 * Thrown when the encryption key that was used to create a JWE has since been
 * rotated out of the grace period and can no longer be used for decryption.
 */
export class KeyRotatedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'KeyRotatedError'
  }
}

/**
 * Thrown when the encryption key referenced by a JWE's `kid` header has been
 * explicitly revoked and is no longer available for decryption.
 */
export class KeyRevokedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'KeyRevokedError'
  }
}

/**
 * Thrown when a JWE token has been explicitly blocked (e.g. after a single-use
 * token has already been consumed).
 */
export class TokenRevokedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'TokenRevokedError'
  }
}

/**
 * Thrown when a token with a finite `use` limit has been presented more times
 * than the limit allows.
 */
export class UsageLimitExceededError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'UsageLimitExceededError'
  }
}

// --- Identity and Trust Failures ---

/**
 * Thrown when the hash of an executable no longer matches the previously
 * approved hash stored in the trust manifest (TOFU conflict).
 *
 * Callers must re-approve the executable before a new token can be issued for
 * it.
 */
export class IdentityMismatchError extends VaultError {
  /**
   * The hash that was recorded in the trust manifest at approval time.
   */
  readonly previousHash: string

  /**
   * The hash computed from the executable at the current moment.
   */
  readonly currentHash: string

  constructor(message: string, previousHash: string, currentHash: string) {
    super(message)
    this.name = 'IdentityMismatchError'
    this.previousHash = previousHash
    this.currentHash = currentHash
  }
}

/**
 * Thrown by {@link VaultKeeper.setup} when the caller does not make an
 * unambiguous executable-trust decision.
 *
 * `setup()` deliberately has no default trust behaviour: the caller must either
 * pass a real `executablePath` (which runs trust-on-first-use verification) or
 * explicitly opt out with `skipTrust: true` (a development-only escape hatch).
 * Supplying neither — or both at once — throws this error rather than silently
 * skipping verification. Passing the retired `'dev'` sentinel as `executablePath`
 * also throws this error. Inspect {@link ExecutableTrustRequiredError.reason} to
 * distinguish the cases.
 *
 * @public
 */
export class ExecutableTrustRequiredError extends VaultError {
  /**
   * Machine-readable discriminator for why the trust choice was rejected.
   * `'missing-choice'` means neither `executablePath` nor `skipTrust: true`
   * was provided, so no trust decision was expressed. `'conflicting-choice'`
   * means both `executablePath` and `skipTrust: true` were provided, which
   * are mutually exclusive intents. `'legacy-dev-sentinel'` means
   * `executablePath` was the retired literal `'dev'` opt-out sentinel, which is
   * no longer supported and must be replaced with `skipTrust: true`.
   */
  readonly reason: 'missing-choice' | 'conflicting-choice' | 'legacy-dev-sentinel'

  constructor(
    message: string,
    reason: 'missing-choice' | 'conflicting-choice' | 'legacy-dev-sentinel',
  ) {
    super(message)
    this.name = 'ExecutableTrustRequiredError'
    this.reason = reason
  }
}

// --- Access Pattern Failures ---

/**
 * Thrown when spawning or running a subprocess fails.
 *
 * This covers a delegated `exec()` call failing due to an invalid request
 * (e.g. a `{{secret}}` placeholder in the `command` field) or a
 * process-level error (e.g. the command binary is not found or cannot be
 * spawned) — and also vaultkeeper's own internal tool invocations (doctor
 * version probes, the keychain/secret-tool/dpapi/yubikey credential helpers),
 * which run through the same subprocess utility. Callers that need to handle
 * only delegated-exec failures should scope their `catch` to the code paths
 * that call `exec()`, not discriminate on this type alone.
 *
 * @public
 */
export class ExecError extends VaultError {
  /**
   * The command that failed to execute.
   */
  readonly command: string

  constructor(message: string, command: string) {
    super(message)
    this.name = 'ExecError'
    this.command = command
  }
}

/**
 * Thrown when a JWE string is invalid or cannot be processed — for example,
 * it is structurally malformed (wrong number of segments, invalid
 * Base64URL), decryption fails (wrong key, tampered ciphertext), or the
 * decrypted payload does not match the expected claims schema.
 *
 * @public
 */
export class InvalidTokenError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'InvalidTokenError'
  }
}

/**
 * Thrown when `SecretAccessor.read()` is called after the accessor has
 * already been consumed.
 *
 * @public
 */
export class AccessorConsumedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'AccessorConsumedError'
  }
}

// --- Infrastructure Failures ---

/**
 * Thrown when a caller requests a signing key algorithm that is not a
 * supported JOSE algorithm identifier. The signing algorithm registry uses
 * strict JOSE identifiers (currently `'EdDSA'`); an unrecognized value is
 * rejected rather than defaulted.
 *
 * @public
 */
export class InvalidAlgorithmError extends VaultError {
  /**
   * The algorithm that was requested.
   */
  readonly algorithm: string

  /**
   * The set of algorithms that are allowed.
   */
  readonly allowed: string[]

  constructor(message: string, algorithm: string, allowed: string[]) {
    super(message)
    this.name = 'InvalidAlgorithmError'
    this.algorithm = algorithm
    this.allowed = allowed
  }
}

/**
 * Thrown when signing-key material cannot be parsed. Two paths raise it. During
 * verification, the supplied public key is not a structurally parseable SPKI PEM
 * public key (or a private key was passed where a public key is required); this
 * is an operational fault distinct from a signature that simply does not verify,
 * which returns `false`. During key use, a stored signing key decrypts cleanly
 * but is not valid private key material — corrupt or tampered on disk — when
 * exporting its public half or signing with it (`getPublicKey`/`signWithKey`).
 * The message never echoes any part of the key material.
 *
 * @public
 */
export class InvalidKeyMaterialError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'InvalidKeyMaterialError'
  }
}

/**
 * Thrown when a named signing key does not exist in the active backend — for
 * example `key export` or `sign` is asked for a name that was never enrolled
 * with `key create`. This is distinct from {@link SecretNotFoundError}: signing
 * keys occupy their own namespace and are never returned as ordinary secrets.
 *
 * @public
 */
export class SigningKeyNotFoundError extends VaultError {
  /**
   * The signing-key name that was requested (the caller-facing `--name`, not
   * the internal namespaced identifier).
   */
  readonly keyName: string

  constructor(message: string, keyName: string) {
    super(message)
    this.name = 'SigningKeyNotFoundError'
    this.keyName = keyName
  }
}

/**
 * Thrown when `key create` (or `createSigningKey`) is asked to enroll a signing
 * key under a name that already exists. Enrollment never silently overwrites an
 * existing key, because a regenerated keypair would invalidate every public key
 * that was previously exported and pinned by a verifier.
 *
 * @public
 */
export class SigningKeyAlreadyExistsError extends VaultError {
  /**
   * The signing-key name that already exists (the caller-facing `--name`, not
   * the internal namespaced identifier).
   */
  readonly keyName: string

  constructor(message: string, keyName: string) {
    super(message)
    this.name = 'SigningKeyAlreadyExistsError'
    this.keyName = keyName
  }
}

/**
 * Thrown when a signing operation (`key create`, `key export`, `sign`) is
 * requested against a backend that does not implement the signing contract.
 * Signing is never silently emulated on a backend that cannot perform it in a
 * key-stays-backend-side manner; inspect {@link SigningNotSupportedError.builtInSigningBackends}
 * for the built-in backend types that do.
 *
 * @public
 */
export class SigningNotSupportedError extends VaultError {
  /** The type identifier of the active backend that cannot sign. */
  readonly backendType: string

  /**
   * The **built-in** backend type identifiers known to implement the signing
   * contract (currently just the `file` backend). This is deliberately a
   * static list of built-ins, not a live capability survey: a consumer that
   * registers its own {@link SigningBackend} is not enumerated here, because
   * discovering that would require instantiating every registered backend —
   * a side effect that must not happen on an error path. A caller can still
   * point a user at a working built-in, and custom backends may implement the
   * contract independently.
   */
  readonly builtInSigningBackends: string[]

  constructor(message: string, backendType: string, builtInSigningBackends: string[]) {
    super(message)
    this.name = 'SigningNotSupportedError'
    this.backendType = backendType
    this.builtInSigningBackends = builtInSigningBackends
  }
}

/**
 * Thrown when an encrypted-at-rest secret entry cannot be decrypted — e.g.
 * the stored ciphertext is truncated/corrupted or the AES-GCM auth tag fails
 * to verify. The message never echoes any part of the secret or key
 * material.
 *
 * @public
 */
export class DecryptionError extends VaultError {
  /**
   * The path of the encrypted entry that failed to decrypt.
   */
  readonly path: string

  constructor(message: string, path: string) {
    super(message)
    this.name = 'DecryptionError'
    this.path = path
  }
}

/**
 * Thrown when a delegated `fetch()` call fails before a `Response` can be
 * produced — for example the URL is malformed or the underlying network
 * request fails (DNS failure, connection refused, TLS error).
 *
 * @public
 */
export class FetchError extends VaultError {
  /**
   * The unresolved URL template that fetch failed to request, with
   * `{{secret}}`/`{{secret:name}}` placeholders left intact. The
   * placeholder-resolved URL is deliberately never stored here, so an
   * injected secret is never exposed.
   */
  readonly url: string

  constructor(message: string, url: string) {
    super(message)
    this.name = 'FetchError'
    this.url = url
  }
}

/**
 * Thrown when a config value fails structural or semantic validation (e.g. a
 * whitespace-only `BackendConfig.path`).
 */
export class ConfigValidationError extends VaultError {
  /**
   * The dotted/bracketed path to the offending config field (e.g.
   * `'backends[0].path'`).
   */
  readonly field: string

  /**
   * The path of the config file that failed validation, when the error
   * originated from loading a file on disk (via `loadConfig`) rather than
   * from validating an in-memory value directly. This is `configDir` joined
   * with `config.json` exactly as provided to `loadConfig` — it is not
   * guaranteed to be absolute (`loadConfig` does not resolve a relative
   * `configDir`).
   */
  readonly configFilePath: string | undefined

  constructor(message: string, field: string, configFilePath?: string) {
    super(message)
    this.name = 'ConfigValidationError'
    this.field = field
    this.configFilePath = configFilePath
  }
}

/**
 * Thrown when a config's `backends[].type` names a backend that is not
 * registered with the {@link BackendRegistry}.
 *
 * A specialization of {@link ConfigValidationError}: an unknown backend type is
 * a semantic schema failure (the config parses and is structurally valid, but
 * names a backend that cannot be created), so it fails config validation the
 * same way `version !== 1` does. It carries the offending `backendType` and the
 * set of `knownTypes` so a consumer — notably `doctor` — can give the same
 * "Available types: …" guidance the runtime {@link BackendUnavailableError}
 * gives, without parsing the human-readable message. This closes the gap where
 * a config with an unknown backend type parsed as valid JSON and passed
 * `doctor` with a false "System ready.", only for the next real command to
 * throw {@link BackendUnavailableError} (issue #215).
 */
export class UnknownBackendTypeError extends ConfigValidationError {
  /** The unregistered backend type named in the config. */
  readonly backendType: string

  /**
   * The backend type identifiers that were registered when validation ran —
   * the valid options to offer in remediation.
   */
  readonly knownTypes: string[]

  constructor(
    message: string,
    field: string,
    backendType: string,
    knownTypes: string[],
    configFilePath?: string,
  ) {
    super(message, field, configFilePath)
    this.name = 'UnknownBackendTypeError'
    this.backendType = backendType
    this.knownTypes = knownTypes
  }
}

/**
 * Thrown when a config file's contents cannot be parsed as JSON.
 *
 * The `message` already embeds the file path, the parse location (when the
 * underlying `SyntaxError` exposes one), and a remediation hint that either
 * points at `vaultkeeper config init` (via the separate `@vaultkeeper/cli`
 * package — this library ships no CLI of its own) or at repairing/replacing
 * the config directly through this library's JS API — see issues #68, #100.
 * `path` and `location` are also exposed individually for callers (e.g.
 * `doctor`) that want to report them as structured fields rather than
 * re-parsing the message.
 */
export class ConfigParseError extends VaultError {
  /**
   * The path of the config file that failed to parse. This is `configDir`
   * joined with `config.json` exactly as provided to `loadConfig` — it is
   * not guaranteed to be absolute (`loadConfig` does not resolve a relative
   * `configDir`).
   */
  readonly path: string

  /**
   * A human-readable parse location (e.g. `'line 3, column 12'`), when one
   * could be derived from the underlying `SyntaxError`.
   */
  readonly location: string | undefined

  constructor(message: string, path: string, location: string | undefined) {
    super(message)
    this.name = 'ConfigParseError'
    this.path = path
    this.location = location
  }
}

/**
 * Thrown during initialization when a required system dependency (e.g. OpenSSL
 * or a native credential helper) is missing or incompatible.
 */
export class SetupError extends VaultError {
  /**
   * The name of the dependency that caused the setup failure.
   */
  readonly dependency: string

  constructor(message: string, dependency: string) {
    super(message)
    this.name = 'SetupError'
    this.dependency = dependency
  }
}

/**
 * Thrown when a filesystem operation fails. Common causes include a
 * permission or access problem, for example the config directory is not
 * writable, but the underlying failure may be any Node.js errno condition,
 * for example the disk is full or a file was expected but a directory was
 * found. Inspect the code property for the specific errno code when one is
 * available.
 */
export class FilesystemError extends VaultError {
  /**
   * The path of the file or directory that caused the error, as provided by
   * the caller. Not guaranteed to be absolute — e.g. `loadConfig` throws this
   * with `configDir` joined with `config.json` exactly as given, without
   * resolving a relative `configDir`.
   */
  readonly path: string

  /**
   * The file operation or access mode that was being attempted when the
   * failure occurred, for example 'read', 'write', 'delete', or 'rwx' for a
   * directory create/access check. Despite the field name, this does not
   * imply the failure was itself a permission problem — it names the
   * attempted operation regardless of the underlying errno, which may be a
   * non-permission code such as ENOSPC or EISDIR.
   */
  readonly permission: string

  /**
   * The Node.js errno code from the underlying filesystem failure, for
   * example EACCES, EPERM, ENOSPC, or EISDIR. Undefined when the error was
   * constructed without an underlying cause, or when that cause did not
   * expose a string errno code. Prefer this over parsing the message text,
   * which is not a contractual format.
   */
  readonly code: string | undefined

  /**
   * @param message - Human-readable description of the failure.
   * @param filePath - The path of the file or directory that caused the error.
   * @param permission - The file operation or access mode being attempted,
   * for example 'read', 'write', 'delete', or 'rwx'. See the `permission`
   * property for why this need not indicate an actual permission problem.
   * @param cause - The underlying error that was caught, if any. Recorded as
   * the standard `Error.cause` and used to populate `code` when it exposes a
   * string errno code.
   */
  constructor(message: string, filePath: string, permission: string, cause?: unknown) {
    super(message)
    this.name = 'FilesystemError'
    this.path = filePath
    this.permission = permission
    this.code = hasErrnoCode(cause) ? cause.code : undefined
    if (cause !== undefined) {
      // Matches the property descriptor the native `new Error(message, {
      // cause })` form installs (non-enumerable), rather than a plain
      // assignment, which would make `cause` enumerable and thus show up in
      // `Object.keys()`/`JSON.stringify()` output unlike a standard cause.
      Object.defineProperty(this, 'cause', {
        value: cause,
        writable: true,
        enumerable: false,
        configurable: true,
      })
    }
  }
}

/**
 * True when `err` is an `Error` carrying a Node.js-style string `code`
 * property — the `NodeJS.ErrnoException` convention used by filesystem and
 * other system-call failures.
 */
function hasErrnoCode(err: unknown): err is Error & { code: string } {
  return err instanceof Error && 'code' in err && typeof err.code === 'string'
}

/**
 * Build a typed FilesystemError from a caught Node.js filesystem failure,
 * describing which resource and operation were involved. The original error
 * is preserved as `cause`, and its errno code, when present, is copied onto
 * the returned error for machine-readable discrimination.
 *
 * @param err - The value caught from the failed filesystem call.
 * @param resourceLabel - A short noun phrase describing what was being
 * accessed, for example 'secret file' or 'wrapping key file'.
 * @param filePath - The path that was being accessed.
 * @param permission - The operation being attempted, for example 'read',
 * 'write', or 'delete'.
 * @internal
 */
export function toFilesystemError(
  err: unknown,
  resourceLabel: string,
  filePath: string,
  permission: string,
): FilesystemError {
  const detail = err instanceof Error ? err.message : String(err)
  return new FilesystemError(
    `Failed to ${permission} ${resourceLabel} at ${filePath}: ${detail}`,
    filePath,
    permission,
    err,
  )
}

/**
 * Thrown when a key rotation is requested while a previous rotation is still
 * within its grace period (i.e. the previous key has not yet been retired).
 */
export class RotationInProgressError extends VaultError {
  constructor(message: string) {
    const trimmed = message.trim()
    const nextSteps =
      'Either wait for the current grace period to elapse before rotating again, ' +
      "or run 'vaultkeeper revoke-key' (or call revokeKey()) to invalidate the previous key " +
      'immediately and clear the grace period.'
    const prefix = trimmed.length === 0 ? '' : `${trimmed}${/[.!?]$/.test(trimmed) ? '' : '.'} `
    super(`${prefix}${nextSteps}`)
    this.name = 'RotationInProgressError'
  }
}

/**
 * Thrown from the `default`/impossible arm of an exhaustive `switch` (or
 * equivalent conditional) over a discriminated union. The constructor
 * parameter is typed `never`, so passing anything other than a value the
 * compiler has already narrowed to `never` — i.e. a union member that was
 * missed — is a compile-time error at the call site, not just a runtime
 * throw. This turns an unhandled union arm into a build failure the moment a
 * new variant is added, rather than a silent fallthrough discovered later at
 * runtime.
 *
 * @example
 * ```ts
 * switch (claims.kty) {
 *   case 'secret':
 *     // ...
 *     break
 *   case 'signing-key':
 *     // ...
 *     break
 *   default:
 *     throw new UnreachableError(claims.kty, 'unrecognized claim kind')
 * }
 * ```
 *
 * @public
 */
export class UnreachableError extends VaultError {
  /**
   * The value that reached the supposedly-unreachable arm, stringified for
   * diagnostics. Always present because `never` at the type level does not
   * guarantee `never` at runtime — a value that bypassed static narrowing
   * (e.g. crossed an untyped boundary such as `JSON.parse`) can still reach
   * this constructor.
   */
  readonly value: string

  constructor(value: never, detail?: string) {
    const stringified = describeUnreachableValue(value)
    const message =
      detail === undefined
        ? `Reached unreachable code: unexpected value ${stringified}`
        : `Reached unreachable code (${detail}): unexpected value ${stringified}`
    super(message)
    this.name = 'UnreachableError'
    this.value = stringified
  }
}

/**
 * Stringifies a value that was statically typed as `never` but has, in
 * practice, reached a runtime check — for example a discriminant value that
 * did not go through the narrowing the type system assumed. `String()` alone
 * is insufficient because it renders `undefined`/objects unhelpfully for
 * diagnostics, so this special-cases the common discriminant shapes.
 *
 * @remarks
 * Typed `unknown` rather than `never` — the caller's argument genuinely is
 * `never` at its call site, but declaring the parameter here as `never` too
 * would make every runtime branch below statically unreachable (the value
 * has no overlap with `string`/`undefined`/`null`), which `no-unnecessary-condition`
 * correctly flags. `unknown` still accepts the `never`-typed caller argument
 * (`never` is a subtype of everything) while letting the runtime checks — the
 * actual point of this function, since a real value can still bypass static
 * narrowing — typecheck normally.
 */
function describeUnreachableValue(value: unknown): string {
  if (typeof value === 'string') {
    return JSON.stringify(value)
  }
  if (value === undefined) {
    return 'undefined'
  }
  if (value === null) {
    return 'null'
  }
  try {
    return JSON.stringify(value)
  } catch {
    // JSON.stringify itself threw (e.g. a circular structure or a BigInt).
    // `String(value)` is avoided here because the value's static type at
    // this point no longer guarantees a meaningful `toString` — fall back to
    // the same tag `Object.prototype.toString` would render as text
    // (`'[object Object]'`, `'[object BigInt]'`, etc.), which is always a
    // safe, defined string regardless of the value's actual shape.
    return Object.prototype.toString.call(value)
  }
}

/**
 * Thrown when a test-only double — a class built purely to fabricate a
 * vaultkeeper-internal signal (e.g. a granted presence check, an unlocked
 * backend) for driving negative test cases — refuses to construct because it
 * detected it is running outside a test environment.
 *
 * @remarks
 * A fabricated signal is, by construction, exactly the thing a real
 * deployment must never be able to forge. A loud, typed refusal at
 * construction time is the last of several stacked guards keeping such a
 * double unreachable from production — see, for example,
 * `PresenceSimulatorBackend` in `@vaultkeeper/test-helpers`. Inspect
 * {@link TestDoubleMisuseError.doubleName} for which class refused to
 * construct and {@link TestDoubleMisuseError.detectedEnvironment} for the
 * environment value that triggered the refusal.
 *
 * @public
 */
export class TestDoubleMisuseError extends VaultError {
  /** The name of the test double class that refused to construct. */
  readonly doubleName: string

  /**
   * The environment value (e.g. `process.env.NODE_ENV`) that triggered the
   * refusal.
   */
  readonly detectedEnvironment: string

  constructor(message: string, doubleName: string, detectedEnvironment: string) {
    super(message)
    this.name = 'TestDoubleMisuseError'
    this.doubleName = doubleName
    this.detectedEnvironment = detectedEnvironment
  }
}

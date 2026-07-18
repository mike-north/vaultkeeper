/**
 * @vaultkeeper/wasm — WASM-backed vaultkeeper SDK for Node.js.
 *
 * Uses the Rust vaultkeeper-core compiled to WebAssembly, with Node.js
 * providing the host platform (file I/O, subprocess execution).
 *
 * @example
 * ```ts
 * import { createVaultKeeper } from '@vaultkeeper/wasm';
 *
 * const vault = await createVaultKeeper({ skipDoctor: true });
 * // setup() requires an explicit executable-trust choice. Bind the token to
 * // the calling executable (the safe, production choice):
 * const token = vault.setup('my-secret', 'secret-value', {
 *   executablePath: process.argv[1],
 * });
 * // In tests/development you may instead deliberately skip the binding with
 * // `{ skipTrust: true }`.
 * const { claims, secret } = vault.authorize(token);
 * // `claims` never contains the raw secret; read it once via the accessor:
 * const first4 = secret.read((value) => value.slice(0, 4));
 * ```
 *
 * @packageDocumentation
 */

// Re-export types
export type {
  WasmHostPlatform,
  VaultKeeperOptions,
  SetupOptions,
  SetupOptionsBase,
  TrustTier,
  KeyStatus,
  VaultClaims,
  VaultResponse,
  SecretAccessor,
  AuthorizeResult,
  PreflightCheckStatus,
  PreflightCheck,
  PreflightResult,
  VaultConfig,
} from './types.js'

export { createNodeHost } from './node-host.js'

// Re-export the typed error hierarchy
export {
  VaultError,
  SecretNotFoundError,
  DecryptionError,
  FilesystemError,
  InvalidTokenError,
  TokenExpiredError,
  KeyRotatedError,
  KeyRevokedError,
  TokenRevokedError,
  UsageLimitExceededError,
  RotationInProgressError,
  AccessorConsumedError,
  ExecutableTrustRequiredError,
  IdentityMismatchError,
  BackendLockedError,
  DeviceNotPresentError,
  AuthorizationDeniedError,
  NotCapableError,
  PresenceDeclinedError,
  PresenceTimeoutError,
  BackendUnavailableError,
  PluginNotFoundError,
  ExecError,
  InvalidAlgorithmError,
  InvalidKeyMaterialError,
  SigningKeyNotFoundError,
  SigningKeyAlreadyExistsError,
  SigningNotSupportedError,
  FetchError,
  ConfigValidationError,
  UnknownBackendTypeError,
  ConfigParseError,
  SetupError,
} from './errors.js'
export type { ExecutableTrustRequiredReason } from './errors.js'

// Lazy-load the WASM module
import type {
  AuthorizeResult,
  PreflightResult,
  SecretAccessor,
  SetupOptions,
  VaultClaims,
  VaultConfig,
  VaultKeeperOptions,
  VaultResponse,
} from './types.js'

import { createNodeHost } from './node-host.js'
import { InvalidTokenError, mapWasmError } from './errors.js'

// The WASM module types
type WasmBindings = typeof import('../wasm/vaultkeeper_wasm.js')
type WasmVaultKeeperInstance = Awaited<ReturnType<WasmBindings['createVaultKeeper']>>
type WasmAuthorizationInstance = ReturnType<WasmVaultKeeperInstance['authorize']>

let wasmBindings: WasmBindings | undefined

async function loadWasm(): Promise<WasmBindings> {
  wasmBindings ??= await import('../wasm/vaultkeeper_wasm.js')
  return wasmBindings
}

/** Run a synchronous WASM call, re-throwing failures as typed {@link VaultError}s. */
function callSync<T>(fn: () => T): T {
  try {
    return fn()
  } catch (thrown) {
    throw mapWasmError(thrown)
  }
}

/** Run an async WASM call, re-throwing failures as typed {@link VaultError}s. */
async function callAsync<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (thrown) {
    throw mapWasmError(thrown)
  }
}

/**
 * Describe a runtime value's type for a type-guard error message. Distinguishes
 * the cases that actually reach these guards from untyped JS callers — `null`,
 * arrays, and Promises (an un-awaited `setup()` call is a common mistake) — from
 * a bare `typeof`, which would report all three unhelpfully as `'object'`. The
 * article is chosen to read cleanly: `undefined` takes none ("received
 * undefined"), `object` takes "an", every other `typeof` takes "a".
 */
function describeType(value: unknown): string {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'an array'
  if (value instanceof Promise) return 'a Promise (did you forget to await?)'
  const type = typeof value
  if (type === 'undefined') return 'undefined'
  if (type === 'object') return 'an object'
  return `a ${type}`
}

/**
 * Reject a non-string argument before it crosses the WASM boundary. The
 * generated wasm-bindgen glue reads a JS string's bytes directly
 * (`passStringToWasm0`); handing it a number, object, or un-awaited Promise
 * corrupts that read and crashes the process with an opaque native
 * `'memory access out of bounds'` fault instead of a catchable error (issue
 * #192). Guarding the JS type here turns that into a clear `TypeError`.
 *
 * `value` is typed `unknown` rather than `string` on purpose: these wrapper
 * methods are reachable from untyped JavaScript, where the declared `string`
 * parameter type is not enforced at runtime, so the check is genuinely
 * load-bearing (and not an unnecessary condition on an already-`string` value).
 */
function ensureStringArg(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string') {
    throw new TypeError(`${label} must be a string, but received ${describeType(value)}`)
  }
}

/**
 * `authorize()`-specific analogue of {@link ensureStringArg}. Because the
 * argument is a JWE token, a non-string is surfaced as {@link InvalidTokenError}
 * — the same typed error a malformed token *string* already produces — so that
 * every bad-token input to `authorize()` is catchable under one type. Prevents
 * the same native `'memory access out of bounds'` fault described above (issue
 * #192).
 */
function ensureJweString(value: unknown): asserts value is string {
  if (typeof value !== 'string') {
    throw new InvalidTokenError(
      `authorize() requires the JWE token as a string, but received ${describeType(value)}`,
    )
  }
}

/**
 * One-time secret accessor backed by a {@link WasmAuthorization}. The plaintext
 * is held in WASM memory until `read()` moves it out exactly once.
 */
class WasmSecretAccessor implements SecretAccessor {
  readonly #auth: WasmAuthorizationInstance

  constructor(auth: WasmAuthorizationInstance) {
    this.#auth = auth
  }

  get available(): boolean {
    return this.#auth.secretAvailable
  }

  read<T>(fn: (secret: string) => T): T {
    // readSecret() throws an `accessor-consumed` error on the second call,
    // which callSync maps to AccessorConsumedError.
    const secret = callSync(() => this.#auth.readSecret())
    return fn(secret)
  }
}

/**
 * A VaultKeeper instance backed by Rust/WASM.
 *
 * Provides the same API as the pure TypeScript VaultKeeper but with
 * the Rust core handling all crypto, token lifecycle, and business logic.
 */
export class VaultKeeper {
  #inner: WasmVaultKeeperInstance

  private constructor(inner: WasmVaultKeeperInstance) {
    this.#inner = inner
  }

  /**
   * Create a new VaultKeeper instance.
   *
   * @param options - Initialization options (e.g., `skipDoctor`)
   * @param configDir - Override the config directory (default: platform standard)
   */
  static async create(options?: VaultKeeperOptions, configDir?: string): Promise<VaultKeeper> {
    const bindings = await loadWasm()
    const host = createNodeHost(configDir)
    const inner = await callAsync(() => bindings.createVaultKeeper(host, options ?? {}))
    return new VaultKeeper(inner)
  }

  /**
   * Run doctor preflight checks.
   *
   * @remarks
   * Returns the same required-vs-informational `PreflightResult` model as the
   * `vaultkeeper` library and CLI. Note this runs the **unscoped** preflight: it
   * is not narrowed to the `file` backend this SDK uses, so the platform-native
   * credential tool (`security`/`powershell`/`secret-tool`) is reported
   * `required: true` even though nothing here uses it. For this SDK's
   * file-backend usage treat that entry as an inventory signal, not a readiness
   * gate — only `openssl` genuinely gates file-backend operation. See the
   * package README's "Doctor / preflight checks" section.
   */
  async doctor(): Promise<PreflightResult> {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- WASM boundary: wasm-bindgen returns untyped JsValue
    return callAsync(() => this.#inner.doctor())
  }

  /**
   * Create a JWE token encapsulating a secret.
   *
   * @remarks
   * **Explicit executable-trust choice required.** Like the TypeScript
   * `vaultkeeper` library's `setup()`, this method no longer defaults to
   * skipping the executable-identity binding. The caller must make an
   * unambiguous decision via {@link SetupOptions}: provide exactly one of
   * `executablePath` (verify and bind the calling executable's identity into
   * the token) or `skipTrust`
   * (`true` — a development-only opt-out). Supplying neither — or both — or the
   * retired `'dev'` sentinel as `executablePath` throws
   * {@link ExecutableTrustRequiredError} rather than silently minting an unbound
   * `'dev'` token. Inspect the error's `reason` (`'missing-choice'` |
   * `'conflicting-choice'` | `'legacy-dev-sentinel'`) to distinguish the cases.
   *
   * **Executable-trust verification.** When `executablePath` is supplied, the
   * executable is hashed and run through trust verification (Sigstore →
   * trust-manifest match → TOFU first-encounter), and the verified hash is bound
   * into the token's `exe` claim. A hash that conflicts with a previously
   * approved value throws {@link IdentityMismatchError}. The first-encounter
   * TOFU record is persisted only after the token has been minted, so a failed
   * `setup()` never leaves a premature trust record behind.
   *
   * **Backend divergence.** Unlike the TypeScript `vaultkeeper` library's
   * `setup(secretName, options?)`, this method does not read from the backend —
   * it mints the token directly from `secretValue`. It never calls
   * {@link VaultKeeper.store} / {@link VaultKeeper.retrieve} or looks at
   * anything already persisted under `secretName`, so a prior `store()` call has
   * no effect on what `setup()` encapsulates. This is an intentional divergence
   * between the two SDKs' `setup()` contracts, not a bug.
   *
   * **Seeing a compile error here?** A bare `vault.setup('NAME', 'value')` or
   * `vault.setup('NAME', 'value', {})` fails to typecheck (e.g. TS2554
   * "Expected 3 arguments, but got 2" or TS2345 "Argument … is not assignable")
   * precisely because the mandatory trust choice is missing. The fix is to add
   * **exactly one** of `executablePath: '<path>'` (verify the caller —
   * production) or `skipTrust: true` (skip verification — development only).
   * Supplying both fails to typecheck for the same reason.
   *
   * @example
   * ```ts
   * // Production: bind the token to the calling executable's identity.
   * const token = await vault.setup('MY_API_KEY', 'secret-value', {
   *   executablePath: '/usr/local/bin/my-tool',
   * })
   *
   * // Local development: skip executable-trust verification.
   * const devToken = await vault.setup('MY_API_KEY', 'secret-value', { skipTrust: true })
   * ```
   *
   * @throws {@link ExecutableTrustRequiredError} If neither `executablePath` nor
   *   `skipTrust: true` is provided, if both are, or if `executablePath` is the
   *   retired legacy `'dev'` opt-out sentinel (use `skipTrust: true`).
   * @throws {@link IdentityMismatchError} If `executablePath`'s current hash no
   *   longer matches a previously approved value (TOFU conflict).
   * @throws TypeError If `secretName` or `secretValue` is not a string (guards
   *   the WASM boundary against a native memory fault).
   */
  async setup(secretName: string, secretValue: string, options: SetupOptions): Promise<string> {
    ensureStringArg(secretName, 'setup() secretName')
    ensureStringArg(secretValue, 'setup() secretValue')
    // A plain-JavaScript caller can pass no options despite the required type;
    // the WASM core still throws ExecutableTrustRequiredError('missing-choice')
    // for an absent or empty choice, preserving the runtime backstop.
    return callAsync(() => this.#inner.setup(secretName, secretValue, options))
  }

  /**
   * Decrypt and validate a JWE token.
   *
   * The returned `claims` never contain the raw secret value. Read the secret
   * through the one-time {@link SecretAccessor} on `result.secret`.
   *
   * @throws {@link InvalidTokenError} If `jwe` is not a string (e.g. a number,
   *   object, or an un-awaited `setup()` Promise) or is a malformed token
   *   string. The non-string guard runs before the value crosses into WASM,
   *   turning what would otherwise be an opaque native memory fault into this
   *   typed error.
   */
  authorize(jwe: string): AuthorizeResult {
    ensureJweString(jwe)
    const auth = callSync(() => this.#inner.authorize(jwe))
    // The claims/response getters deserialize on the WASM side and can throw,
    // so route them through callSync too — every throw from authorize() must
    // surface as a typed VaultError.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- WASM boundary: wasm-bindgen getter returns untyped JsValue
    const claims = callSync<VaultClaims>(() => auth.claims)
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- WASM boundary: wasm-bindgen getter returns untyped JsValue
    const response = callSync<VaultResponse>(() => auth.response)
    return {
      claims,
      response,
      secret: new WasmSecretAccessor(auth),
    }
  }

  /** Rotate the encryption key. */
  rotateKey(): void {
    callSync(() => {
      this.#inner.rotateKey()
    })
  }

  /** Emergency key revocation — removes previous key and generates a new current key. */
  revokeKey(): void {
    callSync(() => {
      this.#inner.revokeKey()
    })
  }

  /** Get the current configuration. */
  config(): VaultConfig {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- WASM boundary: wasm-bindgen returns untyped JsValue
    return callSync(() => this.#inner.config())
  }

  /**
   * Store a secret via the file backend.
   *
   * @throws TypeError If `id` or `secret` is not a string (guards the WASM
   *   boundary against a native memory fault).
   */
  async store(id: string, secret: string): Promise<void> {
    ensureStringArg(id, 'store() id')
    ensureStringArg(secret, 'store() secret')
    await callAsync(() => this.#inner.store(id, secret))
  }

  /**
   * Retrieve a secret via the file backend.
   *
   * @throws TypeError If `id` is not a string (guards the WASM boundary against
   *   a native memory fault).
   */
  async retrieve(id: string): Promise<string> {
    ensureStringArg(id, 'retrieve() id')
    return callAsync(() => this.#inner.retrieve(id))
  }

  /**
   * Delete a secret via the file backend.
   *
   * @throws TypeError If `id` is not a string (guards the WASM boundary against
   *   a native memory fault).
   */
  async delete(id: string): Promise<void> {
    ensureStringArg(id, 'delete() id')
    await callAsync(() => this.#inner.delete(id))
  }

  /** Free the underlying WASM resources. */
  dispose(): void {
    this.#inner.free()
  }
}

/**
 * Convenience function to create a VaultKeeper instance.
 *
 * Equivalent to `VaultKeeper.create(options, configDir)`.
 */
export async function createVaultKeeper(
  options?: VaultKeeperOptions,
  configDir?: string,
): Promise<VaultKeeper> {
  return VaultKeeper.create(options, configDir)
}

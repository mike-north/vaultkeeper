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
 * const token = vault.setup('my-secret', 'secret-value');
 * const { claims, secret } = vault.authorize(token);
 * // `claims` never contains the raw secret; read it once via the accessor:
 * const first4 = secret.read((value) => value.slice(0, 4));
 * ```
 */

// Re-export types
export type {
  WasmHostPlatform,
  VaultKeeperOptions,
  SetupOptions,
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
} from './types.js';

export { createNodeHost } from './node-host.js';

// Re-export the typed error hierarchy
export {
  VaultError,
  SecretNotFoundError,
  InvalidTokenError,
  TokenExpiredError,
  KeyRotatedError,
  KeyRevokedError,
  TokenRevokedError,
  UsageLimitExceededError,
  RotationInProgressError,
  AccessorConsumedError,
} from './errors.js';

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
} from './types.js';

import { createNodeHost } from './node-host.js';
import { mapWasmError } from './errors.js';

// The WASM module types
type WasmBindings = typeof import('../wasm/vaultkeeper_wasm.js');
type WasmVaultKeeperInstance = Awaited<ReturnType<WasmBindings['createVaultKeeper']>>;
type WasmAuthorizationInstance = ReturnType<WasmVaultKeeperInstance['authorize']>;

let wasmBindings: WasmBindings | undefined;

async function loadWasm(): Promise<WasmBindings> {
  wasmBindings ??= await import('../wasm/vaultkeeper_wasm.js');
  return wasmBindings;
}

/** Run a synchronous WASM call, re-throwing failures as typed {@link VaultError}s. */
function callSync<T>(fn: () => T): T {
  try {
    return fn();
  } catch (thrown) {
    throw mapWasmError(thrown);
  }
}

/** Run an async WASM call, re-throwing failures as typed {@link VaultError}s. */
async function callAsync<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (thrown) {
    throw mapWasmError(thrown);
  }
}

/**
 * One-time secret accessor backed by a {@link WasmAuthorization}. The plaintext
 * is held in WASM memory until `read()` moves it out exactly once.
 */
class WasmSecretAccessor implements SecretAccessor {
  readonly #auth: WasmAuthorizationInstance;

  constructor(auth: WasmAuthorizationInstance) {
    this.#auth = auth;
  }

  get available(): boolean {
    return this.#auth.secretAvailable;
  }

  read<T>(fn: (secret: string) => T): T {
    // readSecret() throws an `accessor-consumed` error on the second call,
    // which callSync maps to AccessorConsumedError.
    const secret = callSync(() => this.#auth.readSecret());
    return fn(secret);
  }
}

/**
 * A VaultKeeper instance backed by Rust/WASM.
 *
 * Provides the same API as the pure TypeScript VaultKeeper but with
 * the Rust core handling all crypto, token lifecycle, and business logic.
 */
export class VaultKeeper {
  #inner: WasmVaultKeeperInstance;

  private constructor(inner: WasmVaultKeeperInstance) {
    this.#inner = inner;
  }

  /**
   * Create a new VaultKeeper instance.
   *
   * @param options - Initialization options (e.g., `skipDoctor`)
   * @param configDir - Override the config directory (default: platform standard)
   */
  static async create(
    options?: VaultKeeperOptions,
    configDir?: string,
  ): Promise<VaultKeeper> {
    const bindings = await loadWasm();
    const host = createNodeHost(configDir);
    const inner = await callAsync(() => bindings.createVaultKeeper(host, options ?? {}));
    return new VaultKeeper(inner);
  }

  /** Run doctor preflight checks. */
  async doctor(): Promise<PreflightResult> {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- WASM boundary: wasm-bindgen returns untyped JsValue
    return callAsync(() => this.#inner.doctor());
  }

  /** Create a JWE token encapsulating a secret. */
  setup(secretName: string, secretValue: string, options?: SetupOptions): string {
    return callSync(() => this.#inner.setup(secretName, secretValue, options ?? {}));
  }

  /**
   * Decrypt and validate a JWE token.
   *
   * The returned `claims` never contain the raw secret value. Read the secret
   * through the one-time {@link SecretAccessor} on `result.secret`.
   */
  authorize(jwe: string): AuthorizeResult {
    const auth = callSync(() => this.#inner.authorize(jwe));
    // The claims/response getters deserialize on the WASM side and can throw,
    // so route them through callSync too — every throw from authorize() must
    // surface as a typed VaultError.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- WASM boundary: wasm-bindgen getter returns untyped JsValue
    const claims = callSync<VaultClaims>(() => auth.claims);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- WASM boundary: wasm-bindgen getter returns untyped JsValue
    const response = callSync<VaultResponse>(() => auth.response);
    return {
      claims,
      response,
      secret: new WasmSecretAccessor(auth),
    };
  }

  /** Rotate the encryption key. */
  rotateKey(): void {
    callSync(() => {
      this.#inner.rotateKey();
    });
  }

  /** Emergency key revocation — removes previous key and generates a new current key. */
  revokeKey(): void {
    callSync(() => {
      this.#inner.revokeKey();
    });
  }

  /** Get the current configuration. */
  config(): VaultConfig {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- WASM boundary: wasm-bindgen returns untyped JsValue
    return callSync(() => this.#inner.config());
  }

  /** Store a secret via the file backend. */
  async store(id: string, secret: string): Promise<void> {
    await callAsync(() => this.#inner.store(id, secret));
  }

  /** Retrieve a secret via the file backend. */
  async retrieve(id: string): Promise<string> {
    return callAsync(() => this.#inner.retrieve(id));
  }

  /** Delete a secret via the file backend. */
  async delete(id: string): Promise<void> {
    await callAsync(() => this.#inner.delete(id));
  }

  /** Free the underlying WASM resources. */
  dispose(): void {
    this.#inner.free();
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
  return VaultKeeper.create(options, configDir);
}

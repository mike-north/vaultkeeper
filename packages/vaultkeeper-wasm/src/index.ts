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
 * const { claims } = vault.authorize(token);
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
  AuthorizeResult,
  PreflightCheckStatus,
  PreflightCheck,
  PreflightResult,
  VaultConfig,
} from './types.js';

export { createNodeHost } from './node-host.js';

// Lazy-load the WASM module
import type {
  AuthorizeResult,
  PreflightResult,
  SetupOptions,
  VaultConfig,
  VaultKeeperOptions,
} from './types.js';

import { createNodeHost } from './node-host.js';

// The WASM module types
type WasmBindings = typeof import('../wasm/vaultkeeper_wasm.js');
type WasmVaultKeeperInstance = Awaited<ReturnType<WasmBindings['createVaultKeeper']>>;

let wasmBindings: WasmBindings | undefined;

async function loadWasm(): Promise<WasmBindings> {
  wasmBindings ??= await import('../wasm/vaultkeeper_wasm.js');
  return wasmBindings;
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
    const inner = await bindings.createVaultKeeper(host, options ?? {});
    return new VaultKeeper(inner);
  }

  /** Run doctor preflight checks. */
  async doctor(): Promise<PreflightResult> {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- WASM boundary: wasm-bindgen returns untyped JsValue
    return this.#inner.doctor();
  }

  /** Create a JWE token encapsulating a secret. */
  setup(secretName: string, secretValue: string, options?: SetupOptions): string {
    return this.#inner.setup(secretName, secretValue, options ?? {});
  }

  /** Decrypt and validate a JWE token. */
  authorize(jwe: string): AuthorizeResult {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- WASM boundary: wasm-bindgen returns untyped JsValue
    return this.#inner.authorize(jwe);
  }

  /** Rotate the encryption key. */
  rotateKey(): void {
    this.#inner.rotateKey();
  }

  /** Get the current configuration. */
  config(): VaultConfig {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- WASM boundary: wasm-bindgen returns untyped JsValue
    return this.#inner.config();
  }

  /** Store a secret via the file backend. */
  async store(id: string, secret: string): Promise<void> {
    await this.#inner.store(id, secret);
  }

  /** Retrieve a secret via the file backend. */
  async retrieve(id: string): Promise<string> {
    return this.#inner.retrieve(id);
  }

  /** Delete a secret via the file backend. */
  async delete(id: string): Promise<void> {
    await this.#inner.delete(id);
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

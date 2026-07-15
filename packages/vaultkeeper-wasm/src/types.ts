/**
 * Host platform interface that bridges Node.js OS calls to the WASM module.
 *
 * Implementations of this interface are passed to the WASM VaultKeeper
 * constructor to provide file I/O and subprocess execution.
 */
export interface WasmHostPlatform {
  exec(
    cmd: string,
    args: string[],
    stdin?: Uint8Array,
  ): Promise<{ stdout: Uint8Array; stderr: Uint8Array; exitCode: number }>;
  readFile(path: string): Promise<Uint8Array>;
  writeFile(path: string, content: Uint8Array, mode: number): Promise<void>;
  fileExists(path: string): Promise<boolean>;
  deleteFile(path: string): Promise<void>;
  listDir(path: string): Promise<string[]>;
  platform(): string;
  configDir(): string;
}

/** Options for creating a WasmVaultKeeper instance. */
export interface VaultKeeperOptions {
  skipDoctor?: boolean;
}

/**
 * Options for the setup (token creation) operation.
 *
 * `setup()` requires an explicit executable-trust decision: provide exactly one
 * of {@link SetupOptions.executablePath} or {@link SetupOptions.skipTrust}.
 * Supplying neither, both, or the retired `'dev'` sentinel as `executablePath`
 * throws `ExecutableTrustRequiredError`.
 */
export interface SetupOptions {
  ttlMinutes?: number;
  useLimit?: number;
  /**
   * The calling executable's real path, recorded as a claim label in the minted
   * token. Mutually exclusive with {@link SetupOptions.skipTrust}. The retired
   * `'dev'` sentinel is rejected — use `skipTrust: true` to skip binding a real
   * identity instead.
   *
   * This value is a claim label only. Unlike the TypeScript `vaultkeeper`
   * library's `VaultKeeper.setup()`, this WASM SDK performs no trust-on-first-use
   * (TOFU) verification: the path is copied straight into the token's `exe` claim
   * without hashing the executable, consulting a trust manifest, or throwing on a
   * changed or nonexistent path. Passing `executablePath` here therefore documents
   * an intended identity but does not enforce it. Making WASM `setup()` verify with
   * the same semantics as the TypeScript library is tracked separately (see
   * vaultkeeper issue #165); until then, treat this field as descriptive metadata,
   * not an enforced security boundary.
   */
  executablePath?: string;
  /**
   * Development-only opt-out that deliberately skips binding a real executable
   * identity, producing a `'dev'`-bound token (no executable identity bound).
   * Mutually exclusive with {@link SetupOptions.executablePath}.
   */
  skipTrust?: boolean;
  /**
   * Backend identifier recorded as a claim label in the minted token's `bkd`
   * claim. This is a label only, mirroring the claim-label nature of
   * {@link SetupOptions.executablePath}: it does not select, connect to, or route
   * through a functional backend. Setting `'keychain'`, for example, records the
   * string `'keychain'` in the token without performing any keychain access. This
   * WASM SDK's `setup()` mints the token directly from the supplied secret value
   * and never reads from a backend.
   */
  backendType?: string;
}

/** Trust tier classification. */
export type TrustTier = '1' | '2' | '3';

/** Key status in the vault response. */
export type KeyStatus = 'current' | 'previous' | 'deprecated';

/**
 * Claims embedded in a JWE token, as returned by {@link AuthorizeResult}.
 *
 * The raw secret value (`val`) is deliberately **absent** — it is never part
 * of `authorize()`'s return shape. Read the secret through
 * {@link SecretAccessor} instead.
 */
export interface VaultClaims {
  jti: string;
  exp: number;
  iat: number;
  sub: string;
  exe: string;
  use?: number | null;
  tid: TrustTier;
  bkd: string;
  ref: string;
}

/** Response from token authorization. */
export interface VaultResponse {
  keyStatus: KeyStatus;
  rotatedJwt?: string | null;
}

/**
 * A one-time accessor for the raw secret produced by `authorize()`.
 *
 * Mirrors the `getSecret()` pattern in the TypeScript library: the
 * plaintext secret is exposed only through a single `read()` callback and
 * cannot be read a second time. This keeps the secret out of the default
 * return shape and confines its lifetime to the callback.
 */
export interface SecretAccessor {
  /**
   * Invoke `fn` with the raw secret exactly once and return its result. The
   * secret must not be retained beyond `fn`'s execution.
   *
   * @throws AccessorConsumedError if called after the secret has been read.
   */
  read<T>(fn: (secret: string) => T): T;

  /** Whether the secret is still available (i.e. `read()` has not run). */
  readonly available: boolean;
}

/**
 * Authorization result. Combines the validated claims (secret redacted), the
 * response metadata, and a one-time {@link SecretAccessor} for the plaintext
 * secret.
 */
export interface AuthorizeResult {
  claims: VaultClaims;
  response: VaultResponse;
  secret: SecretAccessor;
}

/** Preflight check status (Rust kebab-case serialization). */
export type PreflightCheckStatus = 'ok' | 'missing' | 'version-unsupported';

/**
 * Individual preflight check result. The Rust struct serializes with
 * `#[serde(rename_all = "camelCase")]`, so the wire/JSON field names here
 * are camelCase (matching this interface), not the Rust source's
 * snake_case.
 *
 * `required` reflects whether this dependency is required for the
 * active/configured backend(s); plugin-backend checks (`op`, `ykman`) are
 * `required: false` when their backend isn't enabled (issue #116).
 */
export interface PreflightCheck {
  name: string;
  status: PreflightCheckStatus;
  version?: string | null;
  reason?: string | null;
  required: boolean;
}

/** Overall preflight result. */
export interface PreflightResult {
  ready: boolean;
  checks: PreflightCheck[];
  warnings: string[];
  nextSteps: string[];
}

/** Vault configuration. */
export interface VaultConfig {
  version: number;
  backends: {
    type: string;
    enabled: boolean;
    plugin?: boolean;
  }[];
  keyRotation: {
    gracePeriodDays: number;
  };
  defaults: {
    ttlMinutes: number;
    trustTier: TrustTier;
  };
  developmentMode?: {
    executables: string[];
  } | null;
}

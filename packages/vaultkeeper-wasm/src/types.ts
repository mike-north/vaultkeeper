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

/** Options for the setup (token creation) operation. */
export interface SetupOptions {
  ttlMinutes?: number;
  useLimit?: number;
  executablePath?: string;
  backendType?: string;
}

/** Trust tier classification. */
export type TrustTier = '1' | '2' | '3';

/** Key status in the vault response. */
export type KeyStatus = 'current' | 'previous' | 'deprecated';

/** Claims embedded in a JWE token. */
export interface VaultClaims {
  jti: string;
  exp: number;
  iat: number;
  sub: string;
  exe: string;
  use?: number | null;
  tid: TrustTier;
  bkd: string;
  val: string;
  ref: string;
}

/** Response from token authorization. */
export interface VaultResponse {
  keyStatus: KeyStatus;
  rotatedJwt?: string | null;
}

/** Authorization result combining claims and response. */
export interface AuthorizeResult {
  claims: VaultClaims;
  response: VaultResponse;
}

/** Preflight check status (Rust kebab-case serialization). */
export type PreflightCheckStatus = 'ok' | 'missing' | 'version-unsupported';

/** Individual preflight check result (Rust snake_case field names). */
export interface PreflightCheck {
  name: string;
  status: PreflightCheckStatus;
  version?: string | null;
  reason?: string | null;
}

/** Overall preflight result. */
// TODO: rename next_steps → nextSteps after wasm-pack rebuild (Rust side already has camelCase serde)
export interface PreflightResult {
  ready: boolean;
  checks: PreflightCheck[];
  warnings: string[];
  next_steps: string[];
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

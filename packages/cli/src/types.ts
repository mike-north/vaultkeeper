/** Options parsed from the `vaultkeeper exec` command line. */
export interface ExecCommandOptions {
  /** Name of the secret to retrieve. */
  secret: string
  /** Environment variable name to inject the secret as. */
  env: string
  /** Path to the calling script for identity verification. */
  caller: string
  /** Human-readable reason for the access request. */
  reason?: string | undefined
  /** Whether to use JWE token caching. */
  cache?: boolean | undefined
  /**
   * Whether to skip output redaction.
   * When `true`, the raw secret value may appear in stdout or stderr.
   * Use only when piping binary data or in controlled environments.
   */
  noRedact?: boolean | undefined
  /** The command and arguments to execute. */
  command: string[]
}

/** Information displayed in the TTY approval prompt. */
export interface ApprovalInfo {
  /** Path to the calling script. */
  caller: string
  /** Trust level description (e.g. "★★☆ Registry (SHA-256: a1b2c3...)"). */
  trustInfo: string
  /** Name of the secret being requested. */
  secret: string
  /** Human-readable reason for the access request. */
  reason?: string | undefined
}

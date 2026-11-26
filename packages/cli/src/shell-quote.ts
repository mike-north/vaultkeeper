/**
 * Quote a string for safe literal use as a single POSIX-shell argument.
 *
 * Wraps the value in single quotes and escapes any embedded single quote as
 * `'\''` (close quote, escaped quote, reopen quote). Use this whenever a
 * user-controlled value — such as a filesystem path — is embedded in a shell
 * command shown in help text or remediation guidance, so a path containing
 * spaces or shell metacharacters can be copied and pasted verbatim without
 * breaking or injecting.
 *
 * @param value - The raw string to quote.
 * @returns The single-quoted, shell-safe representation.
 * @internal
 */
export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`
}

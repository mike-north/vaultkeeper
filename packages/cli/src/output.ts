/**
 * Formatted output helpers for CLI display.
 *
 * @internal
 */

/** Check if stdout is a TTY at call time (not module load time). */
function isTTY(): boolean {
  return process.stdout.isTTY ?? false
}

/** Wrap text in ANSI bold if stdout is a TTY. */
export function bold(text: string): string {
  return isTTY() ? `\x1b[1m${text}\x1b[22m` : text
}

/** Wrap text in ANSI dim if stdout is a TTY. */
export function dim(text: string): string {
  return isTTY() ? `\x1b[2m${text}\x1b[22m` : text
}

/** Format an error for display on stderr. */
export function formatError(err: unknown): string {
  if (err instanceof Error) {
    return `${err.name}: ${err.message}`
  }
  return String(err)
}

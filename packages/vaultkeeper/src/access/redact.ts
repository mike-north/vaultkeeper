/**
 * Secret redaction for captured process output.
 *
 * The single source of truth for how an injected secret value is scrubbed from
 * text. Both the library's delegated `exec()` (which buffers full output) and
 * the CLI's streaming `RedactingStream` (which redacts live) route their
 * substitution through {@link redactSecrets}, so the redaction behavior can
 * never drift between the two surfaces.
 */

/**
 * The token substituted for a redacted secret value.
 *
 * @public
 */
export const REDACTED = '[REDACTED]'

/**
 * Replace every occurrence of each secret value in `text` with `replacement`.
 *
 * Empty secret values are skipped: an empty string matches between every
 * character, so redacting it would replace the whole text. This is used to
 * scrub captured child-process `stdout`/`stderr` so a secret injected into a
 * delegated command never surfaces in the returned output.
 *
 * @param text - The text to scrub.
 * @param secrets - The secret values to redact. Every non-empty value has all
 *   of its occurrences replaced.
 * @param replacement - The token to substitute for each occurrence. Defaults to
 *   {@link REDACTED}.
 * @returns `text` with every occurrence of each non-empty secret replaced.
 *
 * @public
 */
export function redactSecrets(
  text: string,
  secrets: readonly string[],
  replacement: string = REDACTED,
): string {
  let result = text
  for (const secret of secrets) {
    if (secret.length > 0) {
      result = result.replaceAll(secret, replacement)
    }
  }
  return result
}

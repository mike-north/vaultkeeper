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
 * This is used to scrub captured child-process `stdout`/`stderr` so a secret
 * injected into a delegated command never surfaces in the returned output.
 *
 * Before redacting, the secret set is normalized so masking is complete and
 * order-independent:
 *
 * - **Empty/whitespace-only values are dropped.** An empty string matches
 *   between every character, and a whitespace-only value matches ubiquitous
 *   whitespace, so redacting either would blank the text rather than a secret.
 * - **Duplicates are removed** so each distinct value is processed once.
 * - **Longer values are redacted first.** If one secret is a substring or
 *   prefix of another — common for keys that share a prefix — redacting the
 *   shorter one first would leave the longer secret's remaining suffix visible
 *   (redacting `"abc"` before `"abc123"` yields `"[REDACTED]123"`, leaking
 *   `"123"`). Sorting by length descending guarantees each longer value is
 *   fully masked before any shorter substring pass runs.
 *
 * Both arguments are treated fully literally: the secret is matched as a
 * plain substring (never as a regular expression), and `replacement` is
 * inserted verbatim — `String.prototype.replaceAll`'s `$`-substitution
 * patterns are disabled, since a replacement containing `$&` would otherwise
 * re-expand to the matched secret and silently defeat the redaction.
 *
 * @param text - The text to scrub.
 * @param secrets - The secret values to redact. Every non-empty, non-whitespace
 *   value has all of its occurrences replaced.
 * @param replacement - The token to substitute for each occurrence, inserted
 *   literally. Defaults to {@link REDACTED}.
 * @returns `text` with every occurrence of each redactable secret replaced.
 *
 * @public
 */
export function redactSecrets(
  text: string,
  secrets: readonly string[],
  replacement: string = REDACTED,
): string {
  const ordered = [...new Set(secrets)]
    .filter((secret) => secret.trim().length > 0)
    .sort((a, b) => b.length - a.length)

  // '$' doubles to '$$' so replaceAll inserts the replacement verbatim
  // instead of interpreting $&/$`/$' substitution patterns.
  const literalReplacement = replacement.replaceAll('$', '$$$$')
  let result = text
  for (const secret of ordered) {
    result = result.replaceAll(secret, literalReplacement)
  }
  return result
}

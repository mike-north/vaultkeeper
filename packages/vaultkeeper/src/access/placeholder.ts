/**
 * Placeholder replacement utilities for delegated access patterns.
 *
 * Supports two modes:
 * - **Single-secret:** `{{secret}}` is replaced with a single secret value
 * - **Named-secret:** `{{secret:name}}` is replaced with the corresponding
 *   named secret from a `Record<string, string>` map
 */

import { VaultError } from '../errors.js'

/** Literal placeholder for single-secret mode. */
export const PLACEHOLDER = '{{secret}}'

/** Regex matching `{{secret:name}}` named placeholders. */
const NAMED_PLACEHOLDER_RE = /\{\{secret:([^}]+)\}\}/g

/** Regex matching any secret placeholder (named or unnamed). */
export const ANY_PLACEHOLDER_RE = /\{\{secret(?::[^}]+)?\}\}/

/**
 * Replace placeholders in a string with secret values.
 *
 * When `secrets` is a `string`, every `{{secret}}` occurrence is replaced.
 * When `secrets` is a `Record`, every `{{secret:name}}` occurrence is
 * resolved from the corresponding map entry.
 *
 * @param value - The string containing placeholders
 * @param secrets - A single secret string (replaces `{{secret}}`) or a
 *   name-to-value map (replaces `{{secret:name}}`)
 * @returns The string with all matching placeholders resolved
 * @throws {VaultError} If a named placeholder references a name not in the map
 * @internal
 */
export function resolvePlaceholders(
  value: string,
  secrets: string | Record<string, string>,
): string {
  if (typeof secrets === 'string') {
    return value.replaceAll(PLACEHOLDER, secrets)
  }
  return value.replace(NAMED_PLACEHOLDER_RE, (_match, name: string) => {
    const secret = secrets[name]
    if (secret === undefined) {
      const available = Object.keys(secrets).join(', ')
      throw new VaultError(
        `Unknown secret name in placeholder: {{secret:${name}}}. Available names: ${available}`,
      )
    }
    return secret
  })
}

/**
 * Replace placeholders in all values of a string record.
 *
 * @param record - Key-value pairs whose values may contain placeholders
 * @param secrets - A single secret string or a name-to-value map
 * @returns A new record with all placeholders in values resolved
 * @internal
 */
export function resolvePlaceholdersInRecord(
  record: Record<string, string>,
  secrets: string | Record<string, string>,
): Record<string, string> {
  const result: Record<string, string> = {}
  for (const [key, value] of Object.entries(record)) {
    result[key] = resolvePlaceholders(value, secrets)
  }
  return result
}

/**
 * Delegated HTTP fetch access pattern.
 *
 * Replaces `{{secret}}` or `{{secret:name}}` placeholders in the request
 * URL, headers, and body with actual secret values, then executes the fetch.
 */

import type { FetchRequest } from '../types.js'
import { FetchError } from '../errors.js'
import { resolvePlaceholders, resolvePlaceholdersInRecord } from './placeholder.js'

/**
 * Remove any secret material from an underlying error's text before it is
 * surfaced in a thrown message. Network/DNS/TLS errors routinely embed the
 * requested (placeholder-resolved) URL in their own message — e.g.
 * `getaddrinfo ENOTFOUND host-containing-secret` — so the resolved URL and
 * every raw secret value must be stripped. Uses literal `split`/`join`
 * (not regex) so secret contents are never interpreted as a pattern.
 */
function redactSecretMaterial(
  detail: string,
  resolvedUrl: string,
  urlTemplate: string,
  secretValues: readonly string[],
): string {
  let out = detail
  if (resolvedUrl !== urlTemplate) {
    out = out.split(resolvedUrl).join(urlTemplate)
  }
  for (const value of secretValues) {
    if (value.length > 0) {
      out = out.split(value).join('[REDACTED]')
    }
  }
  return out
}

/**
 * Execute a delegated HTTP fetch with secrets injected into the request.
 *
 * @param secrets - A single secret string (replaces `{{secret}}`) or a
 *   name-to-value map (replaces `{{secret:name}}`)
 * @param request - The fetch request template with placeholders
 * @returns The fetch Response
 * @throws {FetchError} If the URL is malformed or the underlying network
 *   request fails (e.g. DNS failure, connection refused, TLS error).
 * @internal
 */
export async function delegatedFetch(
  secrets: string | Record<string, string>,
  request: FetchRequest,
): Promise<Response> {
  const url = resolvePlaceholders(request.url, secrets)
  const headers =
    request.headers !== undefined
      ? resolvePlaceholdersInRecord(request.headers, secrets)
      : undefined
  const body = request.body !== undefined ? resolvePlaceholders(request.body, secrets) : undefined

  const init: RequestInit = {}
  if (request.method !== undefined) {
    init.method = request.method
  }
  if (headers !== undefined) {
    init.headers = headers
  }
  if (body !== undefined) {
    init.body = body
  }

  try {
    return await fetch(url, init)
  } catch (error) {
    const rawDetail = error instanceof Error ? error.message : String(error)
    // The underlying error's message can embed the placeholder-resolved URL
    // (with the injected secret) — e.g. `getaddrinfo ENOTFOUND <secret-host>`.
    // Redact the resolved URL and every secret value before including it, and
    // report the unresolved template (`request.url`), never the resolved `url`,
    // so no secret is echoed into the thrown message or the `url` field. The
    // original error is deliberately not attached as `cause`: its message
    // cannot be redacted in place and would reintroduce the leak.
    const secretValues = typeof secrets === 'string' ? [secrets] : Object.values(secrets)
    const detail = redactSecretMaterial(rawDetail, url, request.url, secretValues)
    throw new FetchError(`Fetch failed for ${request.url}: ${detail}`, request.url)
  }
}

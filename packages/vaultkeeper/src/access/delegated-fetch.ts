/**
 * Delegated HTTP fetch access pattern.
 *
 * Replaces `{{secret}}` or `{{secret:name}}` placeholders in the request
 * URL, headers, and body with actual secret values for the initial request.
 * Dispatch requires a live capability and covers only that destination.
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
 * @param beforeDispatch - Lease check before handing the prepared request to fetch
 * @returns The Response for a non-redirecting request.
 * @throws {FetchError} If the URL is malformed, the server sends a Fetch
 *   redirect, or the underlying network request fails.
 * @internal
 */
export async function delegatedFetch(
  secrets: string | Record<string, string>,
  request: FetchRequest,
  beforeDispatch?: () => void,
): Promise<Response> {
  // Keep this call's template for diagnostics if the caller reuses the request.
  const { url: urlTemplate, headers, body, method } = request
  const url = resolvePlaceholders(urlTemplate, secrets)

  // Delegation covers the initial destination. Reject redirects in the
  // transport and keep redirect response metadata out of the return value.
  const init: RequestInit = { redirect: 'error' }
  if (method !== undefined) {
    init.method = method
  }
  if (headers !== undefined) {
    init.headers = resolvePlaceholdersInRecord(headers, secrets)
  }
  if (body !== undefined) {
    init.body = resolvePlaceholders(body, secrets)
  }

  /** Keep fetch lookup and transport failures on the same redacted error path. */
  const fetchFailure = (error: unknown): FetchError => {
    const rawDetail = error instanceof Error ? error.message : String(error)
    // The underlying error's message can embed the placeholder-resolved URL
    // (with the injected secret) — e.g. `getaddrinfo ENOTFOUND <secret-host>`.
    // Redact the resolved URL and every secret value before including it, and
    // report the dispatched request's unresolved template, never the resolved `url`,
    // so no secret is echoed into the thrown message or the `url` field. The
    // original error is deliberately not attached as `cause`: its message
    // cannot be redacted in place and would reintroduce the leak.
    const secretValues = typeof secrets === 'string' ? [secrets] : Object.values(secrets)
    const detail = redactSecretMaterial(rawDetail, url, urlTemplate, secretValues)
    return new FetchError(`Fetch failed for ${urlTemplate}: ${detail}`, urlTemplate)
  }

  let dispatch: typeof fetch
  try {
    dispatch = fetch
  } catch (error) {
    throw fetchFailure(error)
  }

  // A lease refusal keeps its authorization error type. Resolve dispatch first
  // because a global getter can run user code before returning the function.
  beforeDispatch?.()
  try {
    return await dispatch(url, init)
  } catch (error) {
    throw fetchFailure(error)
  }
}

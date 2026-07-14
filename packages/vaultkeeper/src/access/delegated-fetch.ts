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
    const detail = error instanceof Error ? error.message : String(error)
    // Use the unresolved URL template (`request.url`), not the placeholder-
    // resolved `url`, so a secret injected into the URL is never echoed
    // into the thrown error's message or `url` field.
    throw new FetchError(`Fetch failed for ${request.url}: ${detail}`, request.url)
  }
}

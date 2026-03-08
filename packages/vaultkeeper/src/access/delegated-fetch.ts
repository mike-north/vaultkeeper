/**
 * Delegated HTTP fetch access pattern.
 *
 * Replaces `{{secret}}` or `{{secret:name}}` placeholders in the request
 * URL, headers, and body with actual secret values, then executes the fetch.
 */

import type { FetchRequest } from '../types.js'
import {
  resolvePlaceholders,
  resolvePlaceholdersInRecord,
} from './placeholder.js'

/**
 * Execute a delegated HTTP fetch with secrets injected into the request.
 *
 * @param secrets - A single secret string (replaces `{{secret}}`) or a
 *   name-to-value map (replaces `{{secret:name}}`)
 * @param request - The fetch request template with placeholders
 * @returns The fetch Response
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
  const body =
    request.body !== undefined
      ? resolvePlaceholders(request.body, secrets)
      : undefined

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

  return fetch(url, init)
}

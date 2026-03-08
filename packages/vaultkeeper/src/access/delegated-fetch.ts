/**
 * Delegated HTTP fetch access pattern.
 *
 * Replaces `{{secret}}` placeholders in the request URL, headers, and body
 * with the actual secret value, then executes the fetch.
 */

import type { FetchRequest } from '../types.js'

const PLACEHOLDER = '{{secret}}'

function replacePlaceholder(value: string, secret: string): string {
  return value.replaceAll(PLACEHOLDER, secret)
}

function replaceInRecord(
  record: Record<string, string>,
  secret: string,
): Record<string, string> {
  const result: Record<string, string> = {}
  for (const [key, value] of Object.entries(record)) {
    result[key] = replacePlaceholder(value, secret)
  }
  return result
}

/**
 * Execute a delegated HTTP fetch with the secret injected into the request.
 *
 * @param secret - The secret value to inject
 * @param request - The fetch request template with `{{secret}}` placeholders
 * @returns The fetch Response
 * @internal
 */
export async function delegatedFetch(
  secret: string,
  request: FetchRequest,
): Promise<Response> {
  const url = replacePlaceholder(request.url, secret)
  const headers =
    request.headers !== undefined
      ? replaceInRecord(request.headers, secret)
      : undefined
  const body =
    request.body !== undefined
      ? replacePlaceholder(request.body, secret)
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

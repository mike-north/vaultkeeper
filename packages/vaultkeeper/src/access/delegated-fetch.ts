/**
 * Delegated HTTP fetch access pattern.
 *
 * Replaces `{{secret}}` or `{{secret:name}}` placeholders in the request
 * URL, headers, and body with actual secret values. The returned response
 * exposes the body stream and safe status information without transport text.
 */

import type { FetchRequest } from '../types.js'
import { FetchError } from '../errors.js'
import { resolvePlaceholders, resolvePlaceholdersInRecord } from './placeholder.js'

/**
 * Keep Fetch's response alive while the detached response owns its body. Node
 * can cancel an unread stream when its transport response is collected. A
 * weak key lets Fetch reclaim abandoned responses and keeps transport metadata
 * off the public object.
 */
const bodyOwners = new WeakMap<Response, Response>()

/**
 * Fetch's finalizer can no longer cancel the source after clone() locks it.
 * Detached responses have no transport URL list, so Node may not register
 * cleanup for their tee branches. Cancel abandoned unread branches so the
 * source can close once neither branch needs it.
 */
const clonedBodies = new FinalizationRegistry<WeakRef<ReadableStream<Uint8Array>>>((bodyRef) => {
  const body = bodyRef.deref()
  if (body === undefined || body.locked) {
    return
  }
  try {
    // The constructor rejects disturbed bodies without reading from the stream.
    // Cancel only if the branch has never been read or canceled by its caller.
    void new Response(body).body?.cancel().catch(() => undefined)
  } catch {
    // A caller can keep using a disturbed stream after dropping its Response.
  }
})

/** Associate an unread tee branch with its detached response until the next clone. */
function trackClonedBody(response: Response): void {
  clonedBodies.unregister(response)
  const body = response.body
  if (body !== null) {
    clonedBodies.register(response, new WeakRef(body), response)
  }
}

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
 * Preserve safe metadata that the Response constructor cannot represent. Each
 * clone carries the same status and redirect flag with native body semantics.
 */
function preserveResponseMetadata(
  response: Response,
  status: number,
  redirected: boolean,
): Response {
  if (response.status !== status) {
    Object.defineProperty(response, 'status', { value: status })
  }
  if (redirected) {
    Object.defineProperty(response, 'redirected', { value: true })
  }

  Object.defineProperty(response, 'clone', {
    value: function clone(this: Response): Response {
      const copy = Response.prototype.clone.call(this)
      trackClonedBody(this)
      trackClonedBody(copy)
      return preserveResponseMetadata(copy, status, redirected)
    },
  })
  return response
}

/**
 * Detach the response from the transport so callers can consume the original
 * body stream without receiving metadata that can contain injected credentials.
 * Any response header name or value and the reason phrase can reflect a URL
 * or credential, including serialized forms that literal redaction would miss.
 */
function sanitizeResponse(transportResponse: Response): Response {
  const { body, status, redirected } = transportResponse
  // Fetch can deliver statuses outside the constructor's range. Use a backing
  // status that permits a body and has the same `ok` value as those statuses.
  const constructorStatus = status >= 200 && status <= 599 ? status : 500
  const response = new Response(body, { status: constructorStatus })
  if (body !== null) {
    bodyOwners.set(response, transportResponse)
  }
  return preserveResponseMetadata(response, status, redirected)
}

/**
 * Execute a delegated HTTP fetch with secrets injected into the request.
 *
 * @param secrets - A single secret string (replaces `{{secret}}`) or a
 *   name-to-value map (replaces `{{secret:name}}`)
 * @param request - The fetch request template with placeholders
 * @returns A detached response carrying the body stream, numeric status, and redirect flag.
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
    return sanitizeResponse(await fetch(url, init))
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

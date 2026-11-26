/**
 * Delegated HTTP fetch access pattern.
 *
 * Replaces `{{secret}}` or `{{secret:name}}` placeholders in the request
 * URL, headers, and body with actual secret values for the initial request.
 * Dispatch requires a live capability and covers only that destination.
 * The returned response exposes the body stream and safe status information
 * without transport text.
 */

import type { FetchRequest } from '../types.js'
import { FetchError } from '../errors.js'
import { detachBody, replaceDetachedBody, splitDetachedBody } from './detached-body.js'
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

/** Safe metadata associated with each detached response for instance cloning. */
const detachedMetadata = new WeakMap<
  Response,
  { readonly status: number; readonly redirected: boolean }
>()

/**
 * Find the writable body slot on an already-detached, symbol-backed Undici
 * response. Older native clones register live streams for cancellation when a
 * Response is collected or keep an extra tee branch alive. Updating the known
 * slot lets the detached streams own cleanup on those versions.
 */
function legacyBodySlot(response: Response, body: ReadableStream<Uint8Array>): object | undefined {
  const key = Object.getOwnPropertySymbols(response).find(
    (symbol) => symbol.description === 'state',
  )
  if (key === undefined || !Object.hasOwn(new Response(), key)) {
    return undefined
  }
  const state: unknown = Object.getOwnPropertyDescriptor(response, key)?.value
  if (typeof state !== 'object' || state === null || !('body' in state)) {
    return undefined
  }
  const slot = state.body
  if (typeof slot !== 'object' || slot === null) {
    return undefined
  }
  const descriptor = Object.getOwnPropertyDescriptor(slot, 'stream')
  return descriptor?.writable === true && descriptor.value === body ? slot : undefined
}

/** Clone the receiver's own body and metadata, even when the method is borrowed. */
function clone(this: Response): Response {
  const metadata = detachedMetadata.get(this)
  if (metadata === undefined) {
    return Response.prototype.clone.call(this)
  }

  const { status, redirected } = metadata
  const previousBody = this.body
  if (previousBody !== null && !previousBody.locked && !this.bodyUsed) {
    const slot = legacyBodySlot(this, previousBody)
    if (slot !== undefined) {
      const branches = replaceDetachedBody(previousBody)
      if (branches !== undefined) {
        Object.defineProperty(slot, 'stream', { value: branches.original })
        return createResponse(branches.copy, status, redirected, this.headers)
      }
    }
  }

  // Native clone validates the body, locks the previous stream, and replaces
  // the receiver's internal body. Previously obtained stream references must
  // no longer be able to read the original branch.
  const nativeClone = Response.prototype.clone.call(this)
  const original = this.body
  const nativeCopy = nativeClone.body
  if (previousBody !== null && original !== null && nativeCopy !== null) {
    const copy = splitDetachedBody(previousBody, original)
    if (copy !== undefined) {
      // The public copy owns a separate upstream branch. A native tee alone
      // retains both public branches while either is in use, so it cannot
      // release an abandoned sibling independently.
      void nativeCopy.cancel().catch(() => undefined)
      return createResponse(copy, status, redirected, nativeClone.headers)
    }
  }
  return preserveResponseMetadata(nativeClone, status, redirected)
}

/** Preserve safe metadata that the constructor cannot represent on instance clones. */
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

  detachedMetadata.set(response, { status, redirected })
  Object.defineProperty(response, 'clone', { value: clone })
  return response
}

/** Build a native Response from safe metadata and a public body branch. */
function createResponse(
  body: ReadableStream<Uint8Array> | null,
  status: number,
  redirected: boolean,
  headers?: Headers,
): Response {
  // Fetch can deliver statuses outside the constructor's range. Use a backing
  // status that permits a body and has the same `ok` value as those statuses.
  const init: ResponseInit = {
    status: status >= 200 && status <= 599 ? status : 500,
    ...(headers === undefined ? {} : { headers }),
  }
  return preserveResponseMetadata(new Response(body, init), status, redirected)
}

/**
 * Detach the response from the transport so callers can consume the original
 * body stream without receiving metadata that can contain injected credentials.
 * Any response header name or value and the reason phrase can reflect a URL
 * or credential, including serialized forms that literal redaction would miss.
 */
function sanitizeResponse(transportResponse: Response): Response {
  const { body, status, redirected } = transportResponse
  return createResponse(
    body === null ? null : detachBody(transportResponse, body),
    status,
    redirected,
  )
}

/**
 * Execute a delegated HTTP fetch with secrets injected into the request.
 *
 * @param secrets - A single secret string (replaces `{{secret}}`) or a
 *   name-to-value map (replaces `{{secret:name}}`)
 * @param request - The fetch request template with placeholders
 * @param beforeDispatch - Lease check before handing the prepared request to fetch
 * @returns A detached response carrying the body stream, numeric status, and redirect flag.
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
    return sanitizeResponse(await dispatch(url, init))
  } catch (error) {
    throw fetchFailure(error)
  }
}

/** Exercises the public delegation boundary with native Fetch and loopback HTTP. */

import { once } from 'node:events'
import { createServer } from 'node:http'
import type { Server, ServerResponse } from 'node:http'
import { setImmediate, setTimeout } from 'node:timers/promises'
import { setFlagsFromString } from 'node:v8'
import { createContext, Script } from 'node:vm'
import { describe, expect, it } from 'vitest'
import { VaultKeeper } from '../../../src/index.js'
import { VaultError } from '../../../src/errors.js'

/** Exercise authorized delegation without accessing a system credential store. */
async function authorizeFixture(secret: string): Promise<{ vault: VaultKeeper; token: string }> {
  const vault = await VaultKeeper.init({
    skipDoctor: true,
    backend: {
      type: 'test',
      displayName: 'Synthetic credential fixture',
      isAvailable: () => Promise.resolve(true),
      store: () => Promise.resolve(),
      retrieve: () => Promise.resolve(secret),
      delete: () => Promise.resolve(),
      exists: () => Promise.resolve(true),
    },
  })
  const jwe = await vault.setup('credential', { skipTrust: true })
  const { token } = await vault.authorize(jwe)
  return { vault, token }
}

/** Use an OS-assigned port so loopback fixtures can run in parallel. */
async function listen(server: Server): Promise<string> {
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (address === null || typeof address === 'string') {
    throw new VaultError('Expected a loopback HTTP server address')
  }
  return `http://127.0.0.1:${String(address.port)}`
}

/** Close held responses and idle Fetch connections even when an assertion fails. */
async function close(server: Server): Promise<void> {
  const closed = once(server, 'close')
  server.close()
  server.closeAllConnections()
  await closed
}

/** Give Fetch finalizers time to run while the server still holds the body. */
async function collectGarbage(): Promise<void> {
  // Only this VM context needs the GC hook. Restore the flag before yielding.
  setFlagsFromString('--expose-gc')
  const context = createContext()
  setFlagsFromString('--no-expose-gc')
  const collect = new Script('gc()')
  for (let attempt = 0; attempt < 12; attempt++) {
    await setTimeout(5)
    collect.runInContext(context)
  }
  await setImmediate()
}

describe('VaultKeeper.fetch response metadata', () => {
  it('hides reflected metadata on a direct request', async () => {
    // A space and non-ASCII text force URL serialization to differ from the injected value.
    const secret = 'synthetic café credential'
    const credentialPath = `?credential=${encodeURIComponent(secret)}`
    const paths: string[] = []
    const server = createServer((request, response) => {
      const url = request.url ?? ''
      paths.push(url)
      // The body is independent of the request URI. Metadata can still reflect it.
      response.writeHead(201, url, {
        'Content-Type': 'application/json',
        'Content-Location': url,
        'X-Result': url,
        [`x-${encodeURIComponent(secret)}`]: 'present',
      })
      response.end('{"stored":true}')
    })
    const endpoint = await listen(server)

    try {
      const { vault, token } = await authorizeFixture(secret)
      const { response, vaultResponse } = await vault.fetch(token, {
        url: `${endpoint}/result?credential={{secret}}`,
      })

      expect(paths).toEqual([`/result${credentialPath}`])
      expect(vaultResponse.keyStatus).toBe('current')
      const clone = response.clone()
      const reclone = clone.clone()
      for (const result of [response, clone, reclone]) {
        expect(result).toBeInstanceOf(Response)
        expect(result.url).toBe('')
        expect(result.redirected).toBe(false)
        expect(result.statusText).toBe('')
        expect([...result.headers]).toEqual([])
        expect(result.type).toBe('default')
        expect(result.status).toBe(201)
        expect(result.ok).toBe(true)
        expect(result.bodyUsed).toBe(false)
      }
      await expect(response.text()).resolves.toBe('{"stored":true}')
      await expect(clone.json()).resolves.toEqual({ stored: true })
      await expect(reclone.arrayBuffer()).resolves.toEqual(
        new TextEncoder().encode('{"stored":true}').buffer,
      )
      expect(response.bodyUsed).toBe(true)
      expect(clone.bodyUsed).toBe(true)
      expect(reclone.bodyUsed).toBe(true)
      expect(() => response.clone()).toThrow(TypeError)
    } finally {
      await close(server)
    }
  })

  it('keeps the native body readable across GC before the first read', async () => {
    const expected = 'body sent after the caller receives the response'
    let pending: ServerResponse | undefined
    const server = createServer((_request, response) => {
      pending = response
      response.writeHead(200, { 'Content-Length': Buffer.byteLength(expected) }).flushHeaders()
    })
    const endpoint = await listen(server)

    try {
      const { vault, token } = await authorizeFixture('synthetic credential')
      const { response } = await vault.fetch(token, { url: `${endpoint}/?credential={{secret}}` })
      if (pending === undefined) {
        throw new VaultError('Expected a response waiting to send its body')
      }
      await collectGarbage()
      expect(response.bodyUsed).toBe(false)
      expect(pending.destroyed).toBe(false)
      pending.end(expected)
      await expect(response.text()).resolves.toBe(expected)
    } finally {
      await close(server)
    }
  })

  it.each(['instance', 'prototype'])(
    'closes a stalled connection after %s clones are collected',
    async (method) => {
      let pending: ServerResponse | undefined
      const server = createServer((_request, response) => {
        pending = response
        response.writeHead(200, { 'Content-Length': '4' }).flushHeaders()
      })
      const endpoint = await listen(server)

      try {
        const { vault, token } = await authorizeFixture('synthetic credential')
        // Leave both tee branches unread and outside the stack collecting them.
        async function abandonClones(): Promise<void> {
          const { response } = await vault.fetch(token, {
            url: `${endpoint}/?credential={{secret}}`,
          })
          if (method === 'prototype') {
            Response.prototype.clone.call(response)
          } else {
            response.clone()
          }
        }

        await abandonClones()
        await collectGarbage()
        expect(pending?.destroyed).toBe(true)
      } finally {
        await close(server)
      }
    },
  )

  it('cancels a stalled response after its ordinary clone is collected', async () => {
    let pending: ServerResponse | undefined
    const server = createServer((_request, response) => {
      pending = response
      response.writeHead(200, { 'Content-Length': '4' }).flushHeaders()
    })
    const endpoint = await listen(server)

    try {
      const { vault, token } = await authorizeFixture('synthetic credential')
      const { response } = await vault.fetch(token, { url: `${endpoint}/?credential={{secret}}` })
      // Cancellation of a tee branch waits until the other branch is released.
      response.clone()
      const body = response.body
      if (pending === undefined || body === null) {
        throw new VaultError('Expected a stalled response with an unread body')
      }
      // Collection can trigger a close before an explicit cancellation settles.
      const closed = once(pending, 'close', { signal: AbortSignal.timeout(1000) })
      await Promise.all([closed, collectGarbage().then(() => body.cancel())])
      expect(pending.destroyed).toBe(true)
    } finally {
      await close(server)
    }
  })

  it('keeps a retained body readable after its ordinary-cloned response is collected', async () => {
    const expected = 'body owned by a retained stream and its sibling clone'
    let pending: ServerResponse | undefined
    const server = createServer((_request, response) => {
      pending = response
      response.writeHead(200, { 'Content-Length': Buffer.byteLength(expected) }).flushHeaders()
    })
    const endpoint = await listen(server)

    try {
      const { vault, token } = await authorizeFixture('synthetic credential')

      /** Retain the unlocked body and the clone without retaining the original response. */
      async function openBranches(): Promise<{
        body: ReadableStream<Uint8Array>
        clone: Response
        responseRef: WeakRef<Response>
      }> {
        const { response } = await vault.fetch(token, { url: `${endpoint}/?credential={{secret}}` })
        const clone = response.clone()
        if (response.body === null) {
          throw new VaultError('Expected the original response to keep its clone branch')
        }
        return { body: response.body, clone, responseRef: new WeakRef(response) }
      }

      const { body, clone, responseRef } = await openBranches()
      await collectGarbage()
      expect(responseRef.deref()).toBeUndefined()
      if (pending === undefined) {
        throw new VaultError('Expected a response waiting to send its body')
      }
      pending.end(expected)
      await expect(Promise.all([new Response(body).text(), clone.text()])).resolves.toEqual([
        expected,
        expected,
      ])
    } finally {
      await close(server)
    }
  })

  it('keeps a stalled body readable when only the native clone reader survives GC', async () => {
    const expected = 'body read through the retained reader'
    let pending: ServerResponse | undefined
    const server = createServer((_request, response) => {
      pending = response
      response.writeHead(200, { 'Content-Length': Buffer.byteLength(expected) }).flushHeaders()
    })
    const endpoint = await listen(server)

    try {
      const { vault, token } = await authorizeFixture('synthetic credential')
      // Keeping the reader is enough to own the stream, even after both Responses are gone.
      async function openCloneReader(): Promise<ReadableStreamDefaultReader<Uint8Array>> {
        const { response } = await vault.fetch(token, { url: `${endpoint}/?credential={{secret}}` })
        const body = Response.prototype.clone.call(response).body
        if (body === null) {
          throw new VaultError('Expected a native clone with a body')
        }
        return body.getReader()
      }

      const reader = await openCloneReader()
      const next = reader.read()
      await collectGarbage()
      if (pending === undefined) {
        throw new VaultError('Expected a response waiting to send its body')
      }
      expect(pending.destroyed).toBe(false)
      pending.end(expected)
      const decoder = new TextDecoder()
      let received = ''
      for (let chunk = await next; !chunk.done; chunk = await reader.read()) {
        received += decoder.decode(chunk.value, { stream: true })
      }
      expect(received + decoder.decode()).toBe(expected)
    } finally {
      await close(server)
    }
  })

  it('reports a partial BYOB element through the body reader', async () => {
    const server = createServer((_request, response) => {
      response.end('x')
    })
    const endpoint = await listen(server)

    try {
      const { vault, token } = await authorizeFixture('synthetic credential')
      const { response } = await vault.fetch(token, { url: `${endpoint}/?credential={{secret}}` })
      const reader = response.body?.getReader({ mode: 'byob' })
      if (reader === undefined) {
        throw new VaultError('Expected a response with a byte stream')
      }
      try {
        // One byte cannot fill a Uint16Array element. Only the read should reject.
        await expect(reader.read(new Uint16Array(8))).rejects.toThrow(TypeError)
        await setImmediate()
      } finally {
        reader.releaseLock()
      }
    } finally {
      await close(server)
    }
  })

  it.concurrent.each([599, 600, 700, 999])(
    'preserves transport status %i and its body',
    async (status) => {
      const expected = 'body for a status accepted by native Fetch'
      const server = createServer((request, response) => {
        const url = request.url ?? ''
        response.writeHead(status, url, { 'Content-Location': url }).end(expected)
      })
      const endpoint = await listen(server)

      try {
        const { vault, token } = await authorizeFixture('synthetic credential')
        const { response } = await vault.fetch(token, {
          url: `${endpoint}/result?credential={{secret}}`,
        })
        const clone = response.clone()
        const nativeClone = Response.prototype.clone.call(response)
        for (const result of [response, clone, clone.clone(), nativeClone]) {
          expect(result.status).toBe(status)
          expect(result.ok).toBe(false)
          expect(result.redirected).toBe(false)
          expect(result.url).toBe('')
          expect(result.statusText).toBe('')
          expect([...result.headers]).toEqual([])
          await expect(result.text()).resolves.toBe(expected)
        }
      } finally {
        await close(server)
      }
    },
  )
})

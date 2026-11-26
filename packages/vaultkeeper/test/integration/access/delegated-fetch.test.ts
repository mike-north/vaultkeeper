/** Exercises the public delegation boundary with native Fetch and real HTTP redirects. */

import { once } from 'node:events'
import { createServer } from 'node:http'
import { describe, expect, it } from 'vitest'
import { VaultKeeper } from '../../../src/index.js'
import { VaultError } from '../../../src/errors.js'

describe('VaultKeeper.fetch response metadata', () => {
  it.concurrent.each([
    { route: 'direct', redirects: false },
    { route: 'redirected', redirects: true },
  ])('hides reflected metadata on a $route request', async ({ redirects }) => {
    // A space and non-ASCII text force URL serialization to differ from the injected value.
    const secret = 'synthetic café credential'
    const credentialPath = `?credential=${encodeURIComponent(secret)}`
    const paths: string[] = []
    const server = createServer((request, response) => {
      const url = request.url ?? ''
      paths.push(url)
      if (url.startsWith('/redirect?')) {
        response.writeHead(302, { Location: url.replace('/redirect?', '/result?') }).end()
        return
      }

      // The body is independent of the request URI. Metadata can still reflect it.
      response.writeHead(201, url, {
        'Content-Type': 'application/json',
        'Content-Location': url,
        'X-Result': url,
        [`x-${encodeURIComponent(secret)}`]: 'present',
      })
      response.end('{"stored":true}')
    })
    server.listen(0, '127.0.0.1')
    await once(server, 'listening')

    try {
      const address = server.address()
      if (address === null || typeof address === 'string') {
        throw new VaultError('Expected a loopback HTTP server address')
      }
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
      const { response, vaultResponse } = await vault.fetch(token, {
        url: `http://127.0.0.1:${String(address.port)}/${redirects ? 'redirect' : 'result'}?credential={{secret}}`,
      })

      expect(paths).toEqual(
        redirects
          ? [`/redirect${credentialPath}`, `/result${credentialPath}`]
          : [`/result${credentialPath}`],
      )
      expect(vaultResponse.keyStatus).toBe('current')
      const clone = response.clone()
      const reclone = clone.clone()
      for (const result of [response, clone, reclone]) {
        expect(result).toBeInstanceOf(Response)
        expect(result.url).toBe('')
        expect(result.redirected).toBe(redirects)
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
      const closed = once(server, 'close')
      server.close()
      server.closeAllConnections()
      await closed
    }
  })
})

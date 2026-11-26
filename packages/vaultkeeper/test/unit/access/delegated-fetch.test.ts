import { describe, it, expect, vi, beforeEach } from 'vitest'
import { delegatedFetch } from '../../../src/access/delegated-fetch.js'
import type { FetchRequest } from '../../../src/access/types.js'
import { FetchError, VaultError } from '../../../src/errors.js'

// Mock the global fetch
const mockFetch = vi.fn<typeof fetch>()
global.fetch = mockFetch

function makeOkResponse(body = ''): Response {
  return new Response(body, { status: 200 })
}

beforeEach(() => {
  mockFetch.mockReset()
})

describe('delegatedFetch', () => {
  describe('URL placeholder replacement', () => {
    it('replaces {{secret}} in the URL', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = { url: 'https://example.com/token/{{secret}}' }

      await delegatedFetch('my-secret', request)

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/token/my-secret',
        expect.any(Object),
      )
    })

    it('replaces multiple occurrences of {{secret}} in the URL', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = { url: 'https://example.com/{{secret}}/{{secret}}' }

      await delegatedFetch('abc', request)

      expect(mockFetch).toHaveBeenCalledWith('https://example.com/abc/abc', expect.any(Object))
    })

    it('leaves URL unchanged when no placeholder present', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = { url: 'https://example.com/path' }

      await delegatedFetch('secret', request)

      expect(mockFetch).toHaveBeenCalledWith('https://example.com/path', expect.any(Object))
    })
  })

  describe('header placeholder replacement', () => {
    it('replaces {{secret}} in header values', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = {
        url: 'https://example.com',
        headers: { Authorization: 'Bearer {{secret}}', 'X-Other': 'static' },
      }

      await delegatedFetch('tok123', request)

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com',
        expect.objectContaining({
          headers: { Authorization: 'Bearer tok123', 'X-Other': 'static' },
        }),
      )
    })

    it('omits headers key from fetch when no headers provided', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = { url: 'https://example.com' }

      await delegatedFetch('s', request)

      const lastCall = mockFetch.mock.lastCall
      expect(lastCall).toBeDefined()
      if (lastCall !== undefined) {
        const [, init] = lastCall
        expect(init).not.toHaveProperty('headers')
      }
    })
  })

  describe('body placeholder replacement', () => {
    it('replaces {{secret}} in the body', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = {
        url: 'https://example.com',
        method: 'POST',
        body: '{"password":"{{secret}}"}',
      }

      await delegatedFetch('p@ssw0rd', request)

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com',
        expect.objectContaining({ body: '{"password":"p@ssw0rd"}' }),
      )
    })

    it('omits body key from fetch when no body provided', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = { url: 'https://example.com' }

      await delegatedFetch('s', request)

      const lastCall = mockFetch.mock.lastCall
      expect(lastCall).toBeDefined()
      if (lastCall !== undefined) {
        const [, init] = lastCall
        expect(init).not.toHaveProperty('body')
      }
    })
  })

  describe('method forwarding', () => {
    it('forwards the method to fetch', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = { url: 'https://example.com', method: 'PUT' }

      await delegatedFetch('s', request)

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com',
        expect.objectContaining({ method: 'PUT' }),
      )
    })

    it('omits method key from fetch when no method provided', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = { url: 'https://example.com' }

      await delegatedFetch('s', request)

      const lastCall = mockFetch.mock.lastCall
      expect(lastCall).toBeDefined()
      if (lastCall !== undefined) {
        const [, init] = lastCall
        expect(init).not.toHaveProperty('method')
      }
    })
  })

  describe('return value', () => {
    it.each([204, 205, 304])('preserves null bodies and numeric status %i', async (status) => {
      mockFetch.mockResolvedValueOnce(new Response(null, { status }))

      const result = await delegatedFetch('s', { url: 'https://example.com' })

      expect(result.status).toBe(status)
      expect(result.ok).toBe(status !== 304)
      expect(result.body).toBeNull()
      await expect(result.text()).resolves.toBe('')
    })

    it('uses only caller-supplied media metadata for body operations', async () => {
      mockFetch.mockResolvedValueOnce(
        new Response('name=value', {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded; reflected=synthetic-value',
          },
        }),
      )

      const result = await delegatedFetch('synthetic-value', { url: 'https://example.com' })
      const blob = await result.clone().blob()
      expect(blob.type).toBe('')
      await expect(blob.text()).resolves.toBe('name=value')

      // eslint-disable-next-line @typescript-eslint/no-deprecated -- Verify the documented native URL-encoded body operation.
      await expect(result.clone().formData()).rejects.toThrow(TypeError)
      result.headers.set('Content-Type', 'application/x-www-form-urlencoded')
      // eslint-disable-next-line @typescript-eslint/no-deprecated -- Verify parsing with the caller's media type.
      const form = await result.clone().formData()
      expect(form.get('name')).toBe('value')
      const typedBlob = await result.blob()
      expect(typedBlob.type).toBe('application/x-www-form-urlencoded')
      await expect(typedBlob.text()).resolves.toBe('name=value')
    })

    it('exposes a stream that can fail after the response has been returned', async () => {
      const stream = new TransformStream<Uint8Array>()
      const writer = stream.writable.getWriter()
      mockFetch.mockResolvedValueOnce(new Response(stream.readable))

      const result = await delegatedFetch('s', { url: 'https://example.com' })
      const interrupted = new FetchError('Synthetic interruption', 'https://example.com')
      const bodyFailure = expect(result.arrayBuffer()).rejects.toBe(interrupted)
      await writer.abort(interrupted)

      expect(result.bodyUsed).toBe(true)
      await bodyFailure
    })
  })

  describe('named-secret mode (Record)', () => {
    it('replaces {{secret:name}} in the URL', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = {
        url: 'https://example.com/{{secret:apiKey}}/data',
      }

      await delegatedFetch({ apiKey: 'key123' }, request)

      expect(mockFetch).toHaveBeenCalledWith('https://example.com/key123/data', expect.any(Object))
    })

    it('replaces multiple named secrets in headers', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = {
        url: 'https://example.com',
        headers: {
          Authorization: 'Bearer {{secret:token}}',
          'X-Api-Key': '{{secret:apiKey}}',
        },
      }

      await delegatedFetch({ token: 'tok', apiKey: 'key' }, request)

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com',
        expect.objectContaining({
          headers: {
            Authorization: 'Bearer tok',
            'X-Api-Key': 'key',
          },
        }),
      )
    })

    it('replaces named secrets in body', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = {
        url: 'https://example.com',
        method: 'POST',
        body: '{"user":"{{secret:user}}","pass":"{{secret:pass}}"}',
      }

      await delegatedFetch({ user: 'alice', pass: 'p@ss' }, request)

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com',
        expect.objectContaining({
          body: '{"user":"alice","pass":"p@ss"}',
        }),
      )
    })

    it('replaces named secrets across url, headers, and body', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = {
        url: 'https://{{secret:host}}/api',
        method: 'POST',
        headers: { Authorization: 'Bearer {{secret:token}}' },
        body: '{"key":"{{secret:apiKey}}"}',
      }

      await delegatedFetch({ host: 'secure.example.com', token: 'jwt', apiKey: 'k' }, request)

      expect(mockFetch).toHaveBeenCalledWith(
        'https://secure.example.com/api',
        expect.objectContaining({
          headers: { Authorization: 'Bearer jwt' },
          body: '{"key":"k"}',
        }),
      )
    })
  })

  describe('negative cases', () => {
    it('wraps a missing global fetch in a typed FetchError', async () => {
      vi.stubGlobal('fetch', mockFetch)
      try {
        Reflect.deleteProperty(globalThis, 'fetch')
        expect('fetch' in globalThis).toBe(false)
        await expect(delegatedFetch('s', { url: 'https://example.invalid' })).rejects.toThrow(
          FetchError,
        )
      } finally {
        vi.unstubAllGlobals()
      }
    })

    // Regression test for the audit in
    // https://github.com/mike-north/vaultkeeper/issues/71: delegatedFetch()
    // previously let a raw fetch() rejection escape untyped, the same
    // "raw error from node:crypto/fetch/spawn reaches the caller" pattern
    // fixed for sign(). It must now surface a typed FetchError.
    it('wraps a fetch rejection in a typed FetchError', async () => {
      mockFetch.mockRejectedValue(new Error('network error'))
      const request: FetchRequest = { url: 'https://example.com' }

      await expect(delegatedFetch('s', request)).rejects.toThrow(FetchError)
      await expect(delegatedFetch('s', request)).rejects.toThrow('network error')
    })

    it('FetchError is an instance of VaultError', async () => {
      mockFetch.mockRejectedValueOnce(new Error('network error'))
      const request: FetchRequest = { url: 'https://example.com' }

      let caught: unknown
      try {
        await delegatedFetch('s', request)
      } catch (error) {
        caught = error
      }
      expect(caught).toBeInstanceOf(VaultError)
    })

    it('does not echo an injected secret from the URL into the FetchError message or url field', async () => {
      // Underlying network errors routinely embed the resolved URL (with the
      // injected secret) in their own message — e.g. DNS failures produce
      // `getaddrinfo ENOTFOUND <host>`. The thrown FetchError must not carry
      // that secret in its message or its `url` field.
      const secret = 'super-secret-value'
      mockFetch.mockRejectedValue(new Error(`getaddrinfo ENOTFOUND example.com/token/${secret}`))
      const request: FetchRequest = { url: 'https://example.com/token/{{secret}}' }

      let caught: unknown
      try {
        await delegatedFetch(secret, request)
      } catch (error) {
        caught = error
      }

      expect(caught).toBeInstanceOf(FetchError)
      const message = caught instanceof Error ? caught.message : ''
      expect(message).not.toContain(secret)
      // Diagnostic detail (the error class/code) is preserved after redaction.
      expect(message).toContain('ENOTFOUND')
      const url = caught instanceof FetchError ? caught.url : ''
      expect(url).not.toContain(secret)
      expect(url).toBe('https://example.com/token/{{secret}}')
    })

    it('redacts a transport diagnostic with the dispatched URL template after request reuse', async () => {
      const secret = 'synthetic-secret'
      const url = 'https://example.com/token/{{secret}}'
      const resolvedUrl = `https://example.com/token/${secret}`
      mockFetch.mockRejectedValueOnce(new Error(`Transport rejected ${resolvedUrl}`))
      const request: FetchRequest = { url }

      const result = delegatedFetch(secret, request)
      request.url = 'https://example.com/later-request'

      await expect(result).rejects.toMatchObject({
        url,
        message: `Fetch failed for ${url}: Transport rejected ${url}`,
      })
    })

    it('redacts a named injected secret from the FetchError message', async () => {
      const secret = 'named-secret-value'
      mockFetch.mockRejectedValue(new Error(`ECONNREFUSED https://example.com/${secret}/resource`))
      const request: FetchRequest = { url: 'https://example.com/{{secret:token}}/resource' }

      let caught: unknown
      try {
        await delegatedFetch({ token: secret }, request)
      } catch (error) {
        caught = error
      }

      expect(caught).toBeInstanceOf(FetchError)
      const message = caught instanceof Error ? caught.message : ''
      expect(message).not.toContain(secret)
      expect(message).toContain('ECONNREFUSED')
    })
  })
})

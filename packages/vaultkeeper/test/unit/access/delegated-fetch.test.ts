import { describe, it, expect, vi, beforeEach } from 'vitest'
import { delegatedFetch } from '../../../src/access/delegated-fetch.js'
import type { FetchRequest } from '../../../src/access/types.js'

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

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/abc/abc',
        expect.any(Object),
      )
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
    it('returns the Response from fetch', async () => {
      const expected = makeOkResponse('hello')
      mockFetch.mockResolvedValueOnce(expected)
      const request: FetchRequest = { url: 'https://example.com' }

      const result = await delegatedFetch('s', request)

      expect(result).toBe(expected)
    })
  })

  describe('named-secret mode (Record)', () => {
    it('replaces {{secret:name}} in the URL', async () => {
      mockFetch.mockResolvedValueOnce(makeOkResponse())
      const request: FetchRequest = {
        url: 'https://example.com/{{secret:apiKey}}/data',
      }

      await delegatedFetch({ apiKey: 'key123' }, request)

      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/key123/data',
        expect.any(Object),
      )
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

      await delegatedFetch(
        { host: 'secure.example.com', token: 'jwt', apiKey: 'k' },
        request,
      )

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
    it('propagates fetch rejection', async () => {
      mockFetch.mockRejectedValueOnce(new Error('network error'))
      const request: FetchRequest = { url: 'https://example.com' }

      await expect(delegatedFetch('s', request)).rejects.toThrow('network error')
    })
  })
})

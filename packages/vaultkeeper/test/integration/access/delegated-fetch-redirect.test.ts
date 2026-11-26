import { once } from 'node:events'
import { createServer } from 'node:http'
import type { Server } from 'node:http'

import { describe, expect, it } from 'vitest'

import { FetchError, VaultKeeper } from '../../../src/index.js'
import { createInMemoryBackend } from '../../helpers/backend.js'

const syntheticSecret = 'synthetic-secret'

async function listen(server: Server): Promise<string> {
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (address === null || typeof address === 'string') {
    expect.unreachable('Expected a TCP listener')
  }
  return `http://127.0.0.1:${String(address.port)}`
}

async function close(server: Server): Promise<void> {
  if (!server.listening) {
    return
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error !== undefined) {
        reject(error)
      } else {
        resolve()
      }
    })
    server.closeAllConnections()
  })
}

async function createDelegation() {
  const backend = createInMemoryBackend()
  await backend.store('test-credential', syntheticSecret)
  const vault = await VaultKeeper.init({ skipDoctor: true, backend })
  const jwe = await vault.setup('test-credential', { skipTrust: true })
  const { token } = await vault.authorize(jwe)
  return { vault, token }
}

describe('VaultKeeper.fetch redirects', () => {
  it.each([301, 302, 303, 307, 308])(
    'rejects a cross-origin %i before sending a follow-up request',
    async (status) => {
      const { vault, token } = await createDelegation()
      let destinationRequests = 0
      let originCredential: string | string[] | undefined
      let originBody = ''
      let location = ''
      const destination = createServer((_request, response) => {
        destinationRequests++
        response.end()
      })
      const origin = createServer((request, response) => {
        originCredential = request.headers['x-api-key']
        request.setEncoding('utf8')
        request.on('data', (chunk: string) => {
          originBody += chunk
        })
        request.on('end', () => {
          response.writeHead(status, { Location: location })
          response.end()
        })
      })

      try {
        location = `${await listen(destination)}/outside-policy`
        const url = `${await listen(origin)}/authorized`
        const outcome = await vault
          .fetch(
            { apiKey: token },
            {
              url,
              method: 'POST',
              headers: { 'X-Api-Key': '{{secret:apiKey}}' },
              body: '{{secret:apiKey}}',
            },
          )
          .catch((error: unknown) => error)

        expect(originCredential).toBe(syntheticSecret)
        expect(originBody).toBe(syntheticSecret)
        expect(destinationRequests).toBe(0)
        expect(outcome).toBeInstanceOf(FetchError)
      } finally {
        await Promise.all([close(origin), close(destination)])
      }
    },
  )

  it('keeps URL substitutions out of a same-origin redirect failure', async () => {
    const { vault, token } = await createDelegation()
    const paths: (string | undefined)[] = []
    const origin = createServer((request, response) => {
      paths.push(request.url)
      if (request.url !== '/clean') {
        response.writeHead(307, { Location: '/clean' })
      }
      response.end()
    })

    try {
      const url = `${await listen(origin)}/token/{{secret}}`
      const outcome = await vault.fetch(token, { url }).catch((error: unknown) => error)

      expect(paths).toEqual([`/token/${syntheticSecret}`])
      expect(outcome).toBeInstanceOf(FetchError)
      expect(outcome).toMatchObject({ url })
      expect(String(outcome)).not.toContain(syntheticSecret)
    } finally {
      await close(origin)
    }
  })

  it('rejects redirects without placeholders and returns ordinary HTTP responses', async () => {
    const { vault, token } = await createDelegation()
    const paths: (string | undefined)[] = []
    const origin = createServer((request, response) => {
      paths.push(request.url)
      if (request.url === '/start') {
        response.writeHead(302, { Location: '/final' })
        response.end()
      } else if (request.url === '/no-location') {
        response.writeHead(302)
        response.end()
      } else if (request.url === '/cached') {
        response.writeHead(304, { Location: '/final' })
        response.end()
      } else {
        response.end('ordinary response')
      }
    })

    try {
      const baseUrl = await listen(origin)
      await expect(vault.fetch(token, { url: `${baseUrl}/start` })).rejects.toBeInstanceOf(
        FetchError,
      )
      await expect(vault.fetch(token, { url: `${baseUrl}/no-location` })).rejects.toBeInstanceOf(
        FetchError,
      )
      expect(paths).toEqual(['/start', '/no-location'])

      const { response } = await vault.fetch(token, { url: `${baseUrl}/final` })
      expect(response.status).toBe(200)
      await expect(response.text()).resolves.toBe('ordinary response')

      const { response: cachedResponse } = await vault.fetch(token, { url: `${baseUrl}/cached` })
      expect(cachedResponse.status).toBe(304)
      expect(paths).toEqual(['/start', '/no-location', '/final', '/cached'])
    } finally {
      await close(origin)
    }
  })
})

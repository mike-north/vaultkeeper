import { describe, it, expect } from 'vitest'
import { RedactingStream } from '../../src/redact.js'

function collectStream(stream: RedactingStream, chunks: Buffer[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const result: Buffer[] = []
    stream.on('data', (chunk: Buffer) => { result.push(chunk) })
    stream.on('end', () => { resolve(Buffer.concat(result).toString('utf8')) })
    stream.on('error', reject)
    for (const chunk of chunks) {
      stream.write(chunk)
    }
    stream.end()
  })
}

describe('RedactingStream', () => {
  it('should redact a secret in a single chunk', async () => {
    const stream = new RedactingStream('my-secret-value')
    const result = await collectStream(stream, [
      Buffer.from('The key is my-secret-value here'),
    ])
    expect(result).toBe('The key is [REDACTED] here')
  })

  it('should redact a secret split across two chunks', async () => {
    const secret = 'my-secret-value'
    const stream = new RedactingStream(secret)
    const result = await collectStream(stream, [
      Buffer.from('The key is my-secr'),
      Buffer.from('et-value here'),
    ])
    expect(result).toBe('The key is [REDACTED] here')
  })

  it('should redact multiple occurrences in one chunk', async () => {
    const stream = new RedactingStream('abc')
    const result = await collectStream(stream, [
      Buffer.from('xabcyabcz'),
    ])
    expect(result).toBe('x[REDACTED]y[REDACTED]z')
  })

  it('should pass through unchanged when secret is empty', async () => {
    const stream = new RedactingStream('')
    const result = await collectStream(stream, [
      Buffer.from('hello world'),
    ])
    expect(result).toBe('hello world')
  })

  it('should pass through data that does not contain the secret', async () => {
    const stream = new RedactingStream('not-present')
    const result = await collectStream(stream, [
      Buffer.from('hello world'),
    ])
    expect(result).toBe('hello world')
  })

  it('should use custom replacement string', async () => {
    const stream = new RedactingStream('secret', '***')
    const result = await collectStream(stream, [
      Buffer.from('my secret value'),
    ])
    expect(result).toBe('my *** value')
  })

  it('should handle secret at the very end of output', async () => {
    const stream = new RedactingStream('end')
    const result = await collectStream(stream, [
      Buffer.from('the end'),
    ])
    expect(result).toBe('the [REDACTED]')
  })

  it('should handle secret at the very start of output', async () => {
    const stream = new RedactingStream('start')
    const result = await collectStream(stream, [
      Buffer.from('starting'),
    ])
    expect(result).toBe('[REDACTED]ing')
  })
})

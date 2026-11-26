import { describe, it, expect } from 'vitest'
import { RedactingStream } from '../../src/redact.js'

async function collectStream(stream: RedactingStream, chunks: Buffer[]): Promise<string> {
  return (await collectBytes(stream, chunks)).toString('utf8')
}

function collectBytes(stream: RedactingStream, chunks: Buffer[]): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const result: Buffer[] = []
    stream.on('data', (chunk: Buffer) => {
      result.push(chunk)
    })
    stream.on('end', () => {
      resolve(Buffer.concat(result))
    })
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
    const result = await collectStream(stream, [Buffer.from('The key is my-secret-value here')])
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
    const result = await collectStream(stream, [Buffer.from('xabcyabcz')])
    expect(result).toBe('x[REDACTED]y[REDACTED]z')
  })

  it('should pass through unchanged when secret is empty', async () => {
    const stream = new RedactingStream('')
    const result = await collectStream(stream, [Buffer.from('hello world')])
    expect(result).toBe('hello world')
  })

  it('should pass through data that does not contain the secret', async () => {
    const stream = new RedactingStream('not-present')
    const result = await collectStream(stream, [Buffer.from('hello world')])
    expect(result).toBe('hello world')
  })

  it('should use custom replacement string', async () => {
    const stream = new RedactingStream('secret', '***')
    const result = await collectStream(stream, [Buffer.from('my secret value')])
    expect(result).toBe('my *** value')
  })

  it('should handle secret at the very end of output', async () => {
    const stream = new RedactingStream('end')
    const result = await collectStream(stream, [Buffer.from('the end')])
    expect(result).toBe('the [REDACTED]')
  })

  it('should handle secret at the very start of output', async () => {
    const stream = new RedactingStream('start')
    const result = await collectStream(stream, [Buffer.from('starting')])
    expect(result).toBe('[REDACTED]ing')
  })

  it('preserves multibyte output split across writes', async () => {
    const bytes = Buffer.from('before 🔐 after')
    const result = await collectBytes(new RedactingStream('secret'), [
      bytes.subarray(0, 9),
      bytes.subarray(9),
    ])
    expect(result).toEqual(bytes)
  })

  it('preserves nonmatching bytes exactly', async () => {
    const bytes = Buffer.from([0xff, 0xfe, 0x00, 0x61, 0x80])
    const result = await collectBytes(new RedactingStream('secret'), [bytes])
    expect(result).toEqual(bytes)
  })

  it('redacts a multibyte secret split at every byte boundary', async () => {
    const secret = '🔐é'
    const input = Buffer.from(`a ${secret}${secret} b`)
    for (let split = 1; split < input.length; split++) {
      const result = await collectStream(new RedactingStream(secret), [
        input.subarray(0, split),
        input.subarray(split),
      ])
      expect(result).toBe('a [REDACTED][REDACTED] b')
    }
  })

  it('does not scan a literal replacement for more matches on a later write', async () => {
    const result = await collectStream(new RedactingStream('abc', '[$&]ab'), [
      Buffer.from('abc'),
      Buffer.from('c more'),
    ])
    expect(result).toBe('[$&]abc more')
  })

  it('emits output before EOF for a one-byte secret', () => {
    const stream = new RedactingStream('x')
    const output: Buffer[] = []
    stream.on('data', (chunk: Buffer) => output.push(chunk))

    stream.write(Buffer.from('progress x'))

    expect(Buffer.concat(output).toString()).toBe('progress [REDACTED]')
    stream.end()
  })
})

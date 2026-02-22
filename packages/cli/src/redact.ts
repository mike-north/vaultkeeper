import { Transform } from 'node:stream'
import type { TransformCallback } from 'node:stream'

/**
 * A Transform stream that replaces all occurrences of a secret value
 * with a replacement string in the piped output.
 *
 * Handles secrets that may be split across chunk boundaries by buffering
 * up to `secret.length - 1` bytes from the end of each chunk.
 *
 * @internal
 */
export class RedactingStream extends Transform {
  readonly #secret: string
  readonly #replacement: string
  #tail: string

  constructor(secret: string, replacement = '[REDACTED]') {
    super()
    this.#secret = secret
    this.#replacement = replacement
    this.#tail = ''
  }

  override _transform(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    if (this.#secret.length === 0) {
      this.push(chunk)
      callback()
      return
    }

    const str = this.#tail + chunk.toString('utf8')
    const redacted = str.replaceAll(this.#secret, this.#replacement)

    // Buffer the last (secret.length - 1) chars in case the secret
    // is split across this chunk and the next one.
    const bufferSize = this.#secret.length - 1
    if (redacted.length > bufferSize) {
      this.#tail = redacted.slice(-bufferSize)
      this.push(redacted.slice(0, -bufferSize))
    } else {
      this.#tail = redacted
    }

    callback()
  }

  override _flush(callback: TransformCallback): void {
    if (this.#tail.length > 0) {
      this.push(this.#tail)
      this.#tail = ''
    }
    callback()
  }
}

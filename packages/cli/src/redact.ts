import { Transform } from 'node:stream'
import type { TransformCallback } from 'node:stream'
import { REDACTED } from 'vaultkeeper'

/**
 * A Transform stream that replaces all occurrences of a secret value
 * with a replacement string in the piped output.
 *
 * Handles secrets that may be split across chunk boundaries by buffering
 * up to one byte fewer than the UTF-8 secret's byte length.
 *
 * @internal
 */
export class RedactingStream extends Transform {
  readonly #secret: Buffer
  readonly #replacement: Buffer
  #tail: Buffer

  constructor(secret: string, replacement = REDACTED) {
    super()
    this.#secret = Buffer.alloc(Buffer.byteLength(secret))
    this.#secret.write(secret)
    this.#replacement = Buffer.from(replacement)
    this.#tail = Buffer.alloc(0)
  }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    const bufferSize = this.#secret.length - 1
    if (bufferSize < 0) {
      this.push(chunk)
      callback()
      return
    }

    // Keep raw input in private storage. Emitted chunks must survive cleanup.
    const bytes = Buffer.alloc(this.#tail.length + chunk.length)
    this.#tail.copy(bytes)
    chunk.copy(bytes, this.#tail.length)
    this.#tail.fill(0)

    try {
      let position = 0
      let match = bytes.indexOf(this.#secret, position)
      while (match !== -1) {
        this.push(Buffer.from(bytes.subarray(position, match)))
        this.push(Buffer.from(this.#replacement))
        // A downstream data listener may destroy the stream during push().
        if (this.destroyed) {
          callback()
          return
        }
        position = match + this.#secret.length
        match = bytes.indexOf(this.#secret, position)
      }

      const end = bytes.length - Math.min(bufferSize, bytes.length - position)
      this.#tail = Buffer.alloc(bytes.length - end)
      bytes.copy(this.#tail, 0, end)
      this.push(Buffer.from(bytes.subarray(position, end)))
    } finally {
      bytes.fill(0)
    }

    callback()
  }

  override _flush(callback: TransformCallback): void {
    const tail = Buffer.from(this.#tail)
    this.#tail.fill(0)
    callback(null, tail)
  }

  override _destroy(error: Error | null, callback: (error: Error | null) => void): void {
    this.#secret.fill(0)
    this.#tail.fill(0)
    callback(error)
  }
}

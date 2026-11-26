import { Transform } from 'node:stream'
import type { TransformCallback } from 'node:stream'
import { REDACTED } from 'vaultkeeper'

/**
 * A Transform stream that replaces all occurrences of a secret value
 * with a replacement string in the piped output.
 *
 * Retains only a trailing prefix of the UTF-8 secret across chunk boundaries.
 *
 * @internal
 */
export class RedactingStream extends Transform {
  readonly #secret: Buffer
  readonly #replacement: Buffer
  readonly #prefixLengths: number[]
  #tail: Buffer

  constructor(secret: string, replacement = REDACTED) {
    super()
    this.#secret = Buffer.alloc(Buffer.byteLength(secret))
    this.#secret.write(secret)
    this.#replacement = Buffer.from(replacement)
    // The prefix table bounds suffix recognition to linear time, even for
    // secrets with many overlapping prefixes.
    this.#prefixLengths = Array.from({ length: this.#secret.length }, () => 0)
    let prefix = 0
    for (let i = 1; i < this.#secret.length; i++) {
      while (prefix > 0 && this.#secret[i] !== this.#secret[prefix]) {
        prefix = this.#prefixLengths[prefix - 1] ?? 0
      }
      if (this.#secret[i] === this.#secret[prefix]) prefix++
      this.#prefixLengths[i] = prefix
    }
    this.#tail = Buffer.alloc(0)
  }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    if (this.#secret.length === 0) {
      this.push(chunk)
      callback()
      return
    }

    // Keep raw input in private storage. Emitted chunks must survive cleanup.
    const bytes = Buffer.alloc(this.#tail.length + chunk.length)
    this.#tail.copy(bytes)
    chunk.copy(bytes, this.#tail.length)
    this.#tail.fill(0)

    // Bound each downstream write without accumulating the entire redacted
    // output, including when replacements are much larger than the secret.
    const output = Buffer.alloc(16 * 1024)
    let used = 0
    const append = (source: Buffer): boolean => {
      let offset = 0
      while (offset < source.length) {
        const count = Math.min(output.length - used, source.length - offset)
        source.copy(output, used, offset, offset + count)
        used += count
        offset += count
        if (used === output.length) {
          this.push(Buffer.from(output))
          used = 0
          if (this.destroyed) return false
        }
      }
      return true
    }

    try {
      let position = 0
      let match = bytes.indexOf(this.#secret, position)
      while (match !== -1) {
        if (!append(bytes.subarray(position, match)) || !append(this.#replacement)) {
          callback()
          return
        }
        position = match + this.#secret.length
        match = bytes.indexOf(this.#secret, position)
      }

      let prefix = 0
      for (let i = position; i < bytes.length; i++) {
        while (prefix > 0 && bytes[i] !== this.#secret[prefix]) {
          prefix = this.#prefixLengths[prefix - 1] ?? 0
        }
        if (bytes[i] === this.#secret[prefix]) prefix++
      }
      const end = bytes.length - prefix
      this.#tail = Buffer.alloc(bytes.length - end)
      bytes.copy(this.#tail, 0, end)
      if (append(bytes.subarray(position, end)) && used > 0) {
        this.push(Buffer.from(output.subarray(0, used)))
      }
    } finally {
      bytes.fill(0)
      output.fill(0)
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

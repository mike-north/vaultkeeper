import type { Readable } from 'node:stream'

/** Find a valid but incomplete UTF-8 suffix that must wait for another chunk. */
function incompleteSuffix(bytes: Buffer): number {
  for (let start = Math.max(0, bytes.length - 3); start < bytes.length; start++) {
    const lead = bytes[start] ?? 0
    const length =
      lead >= 0xc2 && lead <= 0xdf
        ? 2
        : lead >= 0xe0 && lead <= 0xef
          ? 3
          : lead >= 0xf0 && lead <= 0xf4
            ? 4
            : 0
    const available = bytes.length - start
    if (length === 0 || available >= length) continue
    let valid = true
    for (let i = 1; i < available; i++) {
      const byte = bytes[start + i] ?? 0
      if (
        byte < 0x80 ||
        byte > 0xbf ||
        (i === 1 &&
          ((lead === 0xe0 && byte < 0xa0) ||
            (lead === 0xed && byte > 0x9f) ||
            (lead === 0xf0 && byte < 0x90) ||
            (lead === 0xf4 && byte > 0x8f)))
      )
        valid = false
    }
    if (valid) return available
  }
  return 0
}

/** Collect subprocess text while wiping all owned copies of raw output bytes. */
export function collectUtf8(stream: Readable | null) {
  const pending = Buffer.alloc(4)
  let pendingLength = 0
  let text = ''
  let discarded = false

  stream?.on('data', (chunk: Buffer) => {
    let bytes: Buffer | undefined
    try {
      if (!discarded) {
        bytes = Buffer.alloc(pendingLength + chunk.length)
        pending.copy(bytes, 0, 0, pendingLength)
        chunk.copy(bytes, pendingLength)
        pending.fill(0)
        pendingLength = incompleteSuffix(bytes)
        const end = bytes.length - pendingLength
        text += bytes.toString('utf8', 0, end)
        bytes.copy(pending, 0, end)
      }
    } finally {
      bytes?.fill(0)
      chunk.fill(0)
    }
  })

  return {
    finish(): string {
      const result = text + pending.toString('utf8', 0, pendingLength)
      pending.fill(0)
      pendingLength = 0
      text = ''
      return result
    },
    discard(): void {
      discarded = true
      text = ''
      pending.fill(0)
      pendingLength = 0
    },
  }
}

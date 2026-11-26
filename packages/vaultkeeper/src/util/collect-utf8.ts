import type { Readable } from 'node:stream'
import { StringDecoder } from 'node:string_decoder'

/** Collect subprocess text while releasing each raw chunk as soon as it is decoded. */
export function collectUtf8(stream: Readable | null) {
  const decoder = new StringDecoder('utf8')
  let text = ''
  let discarded = false

  stream?.on('data', (chunk: Buffer) => {
    try {
      if (!discarded) {
        text += decoder.write(chunk)
      }
    } finally {
      chunk.fill(0)
    }
  })

  return {
    finish(): string {
      const result = text + decoder.end()
      text = ''
      return result
    },
    discard(): void {
      discarded = true
      text = ''
      decoder.end()
    },
  }
}

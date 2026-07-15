/**
 * Read the entirety of stdin as raw bytes.
 *
 * Used by `sign` and `verify`, where stdin is an arbitrary caller-supplied
 * payload — never a stored secret — and must be passed through byte-for-byte
 * with no trimming or re-encoding.
 *
 * `process.stdin` is never switched to string mode (we never call
 * `setEncoding`), so every chunk is a `Buffer`. A non-Buffer chunk would mean
 * stdin was reconfigured elsewhere — a programming error that could silently
 * break byte fidelity — so we fail loudly rather than re-encode through a
 * string, which keeps the byte-for-byte guarantee above true.
 *
 * @internal
 */
export async function readStdinBytes(): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    if (!Buffer.isBuffer(chunk)) {
      throw new TypeError(
        'readStdinBytes expected raw Buffer chunks from stdin; stdin must not be in string mode.',
      )
    }
    chunks.push(chunk)
  }
  return Buffer.concat(chunks)
}

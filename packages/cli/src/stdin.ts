/**
 * Read the entirety of stdin as raw bytes.
 *
 * Used by `sign` and `verify`, where stdin is an arbitrary caller-supplied
 * payload — never a stored secret — and must be passed through byte-for-byte
 * with no trimming or re-encoding.
 *
 * @internal
 */
export async function readStdinBytes(): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    if (chunk instanceof Buffer) {
      chunks.push(chunk)
    } else if (typeof chunk === 'string') {
      chunks.push(Buffer.from(chunk))
    } else {
      chunks.push(Buffer.from(String(chunk)))
    }
  }
  return Buffer.concat(chunks)
}

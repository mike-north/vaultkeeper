/**
 * Executable hashing utilities.
 */

import * as crypto from 'node:crypto'
import * as fs from 'node:fs'

/**
 * Compute the SHA-256 digest of the file at `filePath`.
 *
 * @param filePath - Absolute or relative path to the binary to hash.
 * @returns Hex-encoded SHA-256 digest string.
 */
export function hashExecutable(filePath: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(filePath)

    stream.on('data', (chunk: Buffer | string) => {
      hash.update(chunk)
    })

    stream.on('end', () => {
      resolve(hash.digest('hex'))
    })

    stream.on('error', (err: Error) => {
      reject(err)
    })
  })
}

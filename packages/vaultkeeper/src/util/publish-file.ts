import { randomUUID } from 'node:crypto'
import * as fs from 'node:fs/promises'
import { toFilesystemError } from '../errors.js'

export function hasErrorCode(error: unknown, code: string): boolean {
  return error instanceof Error && 'code' in error && error.code === code
}

/** Publish complete bytes at a new path. Replacement is reserved for updates. */
export async function publishFile(
  path: string,
  content: Buffer | string,
  description: string,
  replace = false,
): Promise<boolean> {
  const temp = `${path}.${randomUUID()}.tmp`
  let file
  try {
    file = await fs.open(temp, 'wx', 0o600)
  } catch (err) {
    throw toFilesystemError(err, description, temp, 'write')
  }

  try {
    try {
      await file.writeFile(content)
    } finally {
      await file.close()
    }
    if (replace) {
      await fs.rename(temp, path)
    } else {
      await fs.link(temp, path)
    }
    return true
  } catch (err) {
    if (!replace && hasErrorCode(err, 'EEXIST')) return false
    throw toFilesystemError(err, description, path, 'write')
  } finally {
    await fs.unlink(temp).catch(() => undefined)
  }
}

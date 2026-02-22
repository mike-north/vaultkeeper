import * as crypto from 'node:crypto'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import * as os from 'node:os'

/**
 * Resolve the cache directory for JWE tokens.
 *
 * - Linux: `$XDG_RUNTIME_DIR/vaultkeeper/` (tmpfs, secure)
 * - macOS/other: `$TMPDIR/vaultkeeper-<username>/`
 * - Fallback: `os.tmpdir()/vaultkeeper-<username>/`
 *
 * @internal
 */
export function getCacheDir(): string {
  const xdg = process.env.XDG_RUNTIME_DIR
  if (xdg !== undefined && xdg !== '') {
    return path.join(xdg, 'vaultkeeper')
  }

  // Use username for cross-platform compatibility (process.getuid() is
  // undefined on Windows, and uid 0 would cause all users to share a cache).
  const username = os.userInfo().username
  const tmpdir = os.tmpdir()
  return path.join(tmpdir, `vaultkeeper-${username}`)
}

/**
 * Compute a deterministic cache filename from a caller path and secret name.
 * Uses a null-byte separator to prevent collisions between paths that share
 * a prefix (e.g. "/a" + "b" vs "/ab" + "").
 */
function cacheFileName(callerPath: string, secretName: string): string {
  const hash = crypto.createHash('sha256')
  hash.update(callerPath)
  hash.update('\0')
  hash.update(secretName)
  return hash.digest('hex') + '.jwe'
}

/**
 * Read a cached JWE token for the given caller and secret.
 *
 * @returns The cached JWE string, or `undefined` if no cache exists.
 *
 * @internal
 */
export async function readCachedToken(
  callerPath: string,
  secretName: string,
): Promise<string | undefined> {
  const filePath = path.join(getCacheDir(), cacheFileName(callerPath, secretName))
  try {
    const content = await fs.readFile(filePath, 'utf8')
    return content.length > 0 ? content : undefined
  } catch {
    return undefined
  }
}

/**
 * Write a JWE token to the cache.
 *
 * Creates the cache directory (mode 0o700) if it does not exist.
 * Uses atomic write-then-rename to prevent race conditions where another
 * process could read a partially-written file.
 *
 * @internal
 */
export async function writeCachedToken(
  callerPath: string,
  secretName: string,
  jwe: string,
): Promise<void> {
  const dir = getCacheDir()
  await fs.mkdir(dir, { recursive: true, mode: 0o700 })
  const filePath = path.join(dir, cacheFileName(callerPath, secretName))
  // Atomic write: write to a temp file with correct permissions,
  // then rename into place. rename() is atomic on POSIX filesystems.
  const tmpPath = filePath + `.${crypto.randomUUID()}.tmp`
  await fs.writeFile(tmpPath, jwe, { encoding: 'utf8', mode: 0o600 })
  await fs.rename(tmpPath, filePath)
}

/**
 * Remove a cached JWE token.
 *
 * @internal
 */
export async function invalidateCache(
  callerPath: string,
  secretName: string,
): Promise<void> {
  const filePath = path.join(getCacheDir(), cacheFileName(callerPath, secretName))
  try {
    await fs.unlink(filePath)
  } catch {
    // File may not exist — that's fine
  }
}

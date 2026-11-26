import { randomUUID } from 'node:crypto'
import { rmdirSync, unlinkSync } from 'node:fs'
import { mkdir, readdir, realpath, rename, rmdir, unlink, writeFile } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import { performance } from 'node:perf_hooks'
import { kill, pid as currentPid, platform } from 'node:process'
import { setTimeout } from 'node:timers/promises'

/** @param {unknown} error */
function errorCode(error) {
  return error instanceof Error && 'code' in error ? error.code : undefined
}

/** @param {number} pid */
function isDead(pid) {
  try {
    kill(pid, 0)
    return false
  } catch (error) {
    return errorCode(error) === 'ESRCH'
  }
}

/** @param {string} lock */
async function recover(lock) {
  let names
  try {
    names = await readdir(lock)
  } catch (error) {
    if (errorCode(error) === 'ENOENT') return
    throw error
  }

  if (names.length !== 0) {
    const [name] = names
    if (names.length !== 1 || name === undefined) return
    const match = /^([1-9][0-9]{0,9})-[0-9a-f-]{36}$/.exec(name)
    const pid = Number(match?.[1])
    if (!Number.isInteger(pid) || pid > 0x7fffffff || !isDead(pid)) return
    try {
      await unlink(join(lock, name))
    } catch (error) {
      if (errorCode(error) !== 'ENOENT') throw error
    }
  }

  // A successor always arrives as a nonempty directory. Even if it replaces
  // the empty directory before this call, rmdir cannot remove it.
  try {
    await rmdir(lock)
  } catch (error) {
    const code = errorCode(error)
    if (code !== 'ENOENT' && code !== 'ENOTEMPTY' && code !== 'EEXIST') throw error
  }
}

/**
 * This on-disk protocol is shared with the native CLI's host/trust_lock.rs.
 * Publish an already populated directory. Recovery removes only the observed
 * dead owner's unique marker, never a successor's marker. PID reuse is
 * conservative: a marker with a live PID stays in place.
 *
 * The caller creates the parent directory before acquiring the lock.
 *
 * @param {string} lockPath
 * @returns {Promise<() => void>}
 */
export async function lockTrustManifest(lockPath) {
  // Resolve the parent through the filesystem before normalizing the final
  // name: lexical resolution changes the meaning of symlink/.. paths.
  const lock = join(await realpath(dirname(lockPath)), basename(lockPath))
  const owner = `${String(currentPid)}-${randomUUID()}`
  const candidate = lock + '.' + owner
  const marker = join(lock, owner)
  await mkdir(candidate, { mode: 0o700 })
  try {
    await writeFile(join(candidate, owner), '', { flag: 'wx', mode: 0o600 })
    const deadline = performance.now() + 10_000
    for (;;) {
      try {
        await rename(candidate, lock)
      } catch (error) {
        const code = errorCode(error)
        const windowsContention = platform === 'win32' && (code === 'EPERM' || code === 'EACCES')
        if (code !== 'EEXIST' && code !== 'ENOTEMPTY' && !windowsContention) throw error
        if (performance.now() >= deadline) throw error
        await recover(lock)
        await setTimeout(10)
        continue
      }

      return () => {
        // In particular, a cleanup error must not turn a published approval
        // into a reported failure. Recovery can reap the marker after exit.
        try {
          unlinkSync(marker)
        } catch {
          return
        }
        try {
          rmdirSync(lock)
        } catch {
          // A waiter can already have removed or replaced the empty directory.
        }
      }
    }
  } catch (error) {
    await unlink(join(candidate, owner)).catch(() => undefined)
    await rmdir(candidate).catch(() => undefined)
    throw error
  }
}

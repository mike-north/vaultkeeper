/**
 * Node.js implementation of WasmHostPlatform.
 *
 * Bridges Node.js file I/O and child_process to the WASM module's
 * expected host platform interface.
 */

import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { constants } from 'node:fs'
import {
  access,
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  rename,
  rmdir,
  unlink,
  writeFile,
} from 'node:fs/promises'
import { homedir, platform as osPlatform } from 'node:os'
import { basename, dirname, isAbsolute, join } from 'node:path'
import { promisify } from 'node:util'
import type { ExecOptions, HttpFetchRequest, HttpFetchResponse, WasmHostPlatform } from './types.js'

/**
 * The structured failure contract `readFile`/`writeFile`/`deleteFile`/
 * `fileExists` reject with.
 *
 * `JsHostPlatform` (crates/vaultkeeper-wasm/src/wasm_impl.rs,
 * `fs_rejection_to_vault_error`) reads `code`, `message`, and `path` back off
 * the rejected value via `Reflect::get` to build a typed
 * `VaultError::Filesystem` instead of collapsing every rejection into a
 * generic error — this class *is* that wire contract, not an incidental
 * detail of how Node happens to shape `fs` errors today. `code` mirrors
 * Node's `NodeJS.ErrnoException.code` (e.g. `'ENOENT'`, `'EACCES'`) when the
 * underlying failure exposed one; it is `undefined`, never fabricated,
 * otherwise. `path` is preferred over the path argument the Rust call was
 * made with: `writeFile`'s `mkdir` sub-step can fail on a different, more
 * precise directory path than the file path it was nominally about.
 */
class HostFilesystemError extends Error {
  readonly path: string
  readonly code: string | undefined

  constructor(message: string, path: string, code: string | undefined) {
    super(message)
    this.name = 'HostFilesystemError'
    this.path = path
    this.code = code
  }
}

function isErrnoException(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && 'code' in err
}

/** Wrap a caught `fs` failure into the {@link HostFilesystemError} contract. */
function toHostFilesystemError(err: unknown, path: string): HostFilesystemError {
  const message = err instanceof Error ? err.message : String(err)
  const code = isErrnoException(err) && typeof err.code === 'string' ? err.code : undefined
  return new HostFilesystemError(message, path, code)
}

/**
 * Remove inherited macOS ACLs from a new, empty staging directory before
 * creating the file. Clearing the file's ACL would leave a window for other
 * users to open it and retain a descriptor that could read later writes.
 */
async function makeStagingDirPrivate(directory: string): Promise<void> {
  // Node has no macOS ACL API. Use the system utility and pass only the path.
  const operand = isAbsolute(directory) ? directory : `./${directory}`
  const chmod = promisify(execFile)
  // The ACL utility opens the directory, so restore any owner bits stripped
  // by umask while the directory is still empty.
  if (((await lstat(directory)).mode & 0o777) !== 0o700) {
    await chmod('/bin/chmod', ['-h', '700', operand])
  }
  await chmod('/bin/chmod', ['-h', '-N', operand])
  const metadata = await lstat(directory)
  if (!metadata.isDirectory() || (metadata.mode & 0o777) !== 0o700) {
    throw new HostFilesystemError('Staging directory is not owner-only', directory, undefined)
  }
}

/**
 * Publish complete bytes from a fresh inode with the requested permissions.
 * Readers holding the previous inode can only see the previous contents.
 */
async function writeFileSecureUnix(path: string, content: Uint8Array, mode: number): Promise<void> {
  // Preserve the existing destination's write-access check without following
  // symlinks or blocking on a FIFO.
  const previous = await open(
    path,
    constants.O_WRONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  ).catch((err: unknown) => {
    if (isErrnoException(err) && err.code === 'ENOENT') return undefined
    throw err
  })
  if (previous !== undefined) {
    try {
      if (!(await previous.stat()).isFile()) {
        throw new HostFilesystemError('Expected a regular file', path, undefined)
      }
    } finally {
      await previous.close()
    }
  }

  let name: string
  do {
    name = `.vaultkeeper-write-${randomUUID()}`
  } while (name === basename(path))
  // Keep the kernel's resolution of parent components such as symlink/..
  const sibling = `${dirname(path)}/${name}`
  const stagingDir = osPlatform() === 'darwin' ? sibling : undefined
  const staging = stagingDir === undefined ? sibling : `${stagingDir}/contents`
  if (stagingDir !== undefined) {
    await mkdir(stagingDir, { mode: 0o700 })
  }
  try {
    if (stagingDir !== undefined) {
      await makeStagingDirPrivate(stagingDir)
    }
    const file = await open(staging, 'wx', mode)
    try {
      try {
        await file.chmod(mode)
        if (((await file.stat()).mode & 0o777) !== (mode & 0o777)) {
          throw new HostFilesystemError('Requested permissions were not applied', path, undefined)
        }
        await file.writeFile(content)
      } catch (err) {
        await file.close().catch(() => undefined)
        throw err
      }
      await file.close()
      await rename(staging, path)
    } catch (err) {
      await unlink(staging).catch(() => undefined)
      throw err
    }
  } finally {
    if (stagingDir !== undefined) {
      await rmdir(stagingDir).catch(() => undefined)
    }
  }
}

/**
 * Create a Node.js host platform for the WASM module.
 *
 * Uses the standard vaultkeeper config directory:
 * - macOS/Linux: `~/.config/vaultkeeper`
 * - Windows: `%APPDATA%/vaultkeeper`
 *
 * Override with `VAULTKEEPER_CONFIG_DIR` environment variable.
 */
export function createNodeHost(configDirOverride?: string): WasmHostPlatform {
  const configDir = configDirOverride ?? resolveConfigDir()

  return {
    async exec(
      cmd: string,
      args: string[],
      options?: ExecOptions,
    ): Promise<{ stdout: Uint8Array; stderr: Uint8Array; exitCode: number }> {
      return new Promise((resolve) => {
        // Issue #239: `env`/`cwd` are additive on top of the pre-#239
        // behavior. Passing `env: undefined` to `execFile` (the case when
        // `options.env` is omitted) makes the child inherit `process.env`
        // unchanged — Node's own default — so omitting `env` here reproduces
        // the pre-#239 behavior exactly. Merging with `{ ...process.env,
        // ...options.env }` (rather than passing `options.env` alone) means
        // only the named variables are overridden; every other inherited
        // variable is preserved.
        const child = execFile(
          cmd,
          args,
          {
            encoding: 'buffer',
            env: options?.env ? { ...process.env, ...options.env } : undefined,
            cwd: options?.cwd,
          },
          (error, stdout, stderr) => {
            resolve({
              stdout: new Uint8Array(stdout),
              stderr: new Uint8Array(stderr),
              exitCode:
                error?.code !== undefined ? (typeof error.code === 'number' ? error.code : 1) : 0,
            })
          },
        )

        if (options?.stdin !== undefined && child.stdin) {
          child.stdin.write(options.stdin)
          child.stdin.end()
        }
      })
    },

    async readFile(path: string): Promise<Uint8Array> {
      try {
        const buf = await readFile(path)
        return new Uint8Array(buf)
      } catch (err) {
        throw toHostFilesystemError(err, path)
      }
    },

    async writeFile(path: string, content: Uint8Array, mode: number): Promise<void> {
      // Ensure parent directory exists (use path.dirname for cross-platform support)
      const dir = dirname(path)
      if (dir && dir !== '.') {
        try {
          await mkdir(dir, { recursive: true })
        } catch (err) {
          throw toHostFilesystemError(err, dir)
        }
      }
      try {
        if (osPlatform() === 'win32') {
          await writeFile(path, content)
        } else {
          await writeFileSecureUnix(path, content, mode)
        }
      } catch (err) {
        throw toHostFilesystemError(err, path)
      }
    },

    async fileExists(path: string): Promise<boolean> {
      try {
        await access(path)
        return true
      } catch (err) {
        // Mirror the native host's `file_exists` (crates/vaultkeeper-cli/src/host.rs):
        // only a genuine "does not exist" collapses to `false`. Any other
        // failure (e.g. EACCES resolving a parent directory) must surface as
        // a typed error rather than masquerade as "not found".
        if (isErrnoException(err) && err.code === 'ENOENT') {
          return false
        }
        throw toHostFilesystemError(err, path)
      }
    },

    async deleteFile(path: string): Promise<void> {
      try {
        await unlink(path)
      } catch (err) {
        throw toHostFilesystemError(err, path)
      }
    },

    async renameFile(from: string, to: string): Promise<void> {
      try {
        await rename(from, to)
      } catch (err) {
        throw toHostFilesystemError(err, to)
      }
    },

    async listDir(path: string): Promise<string[]> {
      try {
        return await readdir(path)
      } catch {
        return []
      }
    },

    platform(): string {
      const p = osPlatform()
      if (p === 'darwin') return 'darwin'
      if (p === 'win32') return 'win32'
      return 'linux'
    },

    configDir(): string {
      return configDir
    },

    /**
     * Issue #239: bridges `HostPlatform::http_fetch` to Node's global
     * `fetch` (stable since Node 20, this package's minimum supported
     * version). No core consumer calls this yet — see the trait default's
     * doc comment (`crates/vaultkeeper-core/src/backend/types.rs`).
     */
    async httpFetch(request: HttpFetchRequest): Promise<HttpFetchResponse> {
      // `exactOptionalPropertyTypes` forbids assigning `body: undefined`
      // explicitly — omit the property entirely rather than set it to
      // `undefined` when there's no request body.
      const init: RequestInit = { method: request.method, headers: request.headers }
      if (request.body !== undefined) {
        init.body = new Uint8Array(request.body)
      }
      const response = await fetch(request.url, init)
      const body = new Uint8Array(await response.arrayBuffer())
      const headers = Object.fromEntries(response.headers.entries())
      return { status: response.status, headers, body }
    },
  }
}

function resolveConfigDir(): string {
  const envDir = process.env.VAULTKEEPER_CONFIG_DIR
  if (envDir) return envDir

  const p = osPlatform()
  const home = homedir()
  if (p === 'win32')
    return join(process.env.APPDATA ?? join(home, 'AppData', 'Roaming'), 'vaultkeeper')
  // macOS and Linux both use ~/.config/vaultkeeper (matching the TS SDK)
  return join(home, '.config', 'vaultkeeper')
}

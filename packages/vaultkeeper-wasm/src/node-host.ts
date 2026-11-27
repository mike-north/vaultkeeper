/**
 * Node.js implementation of WasmHostPlatform.
 *
 * Bridges Node.js file I/O and child_process to the WASM module's
 * expected host platform interface.
 */

import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import {
  access,
  link,
  open,
  mkdir,
  readdir,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
  chmod,
} from 'node:fs/promises'
import { homedir, platform as osPlatform } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { LockingNotSupportedError } from './errors.js'
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

/** Exclusively reserve an unpublished sibling within the destination's path budget. */
async function openPublicationStage(
  destination: string,
  mode: number,
): Promise<{ temp: string; file: Awaited<ReturnType<typeof open>> }> {
  const targetName = basename(destination)
  const suffixLength = Math.max(2, Buffer.byteLength(targetName) - 2)
  for (let attempt = 0; attempt < 16; attempt++) {
    // Separate internal publication files from the caller's own `.s` stages.
    const name = `.v${randomBytes(12).toString('base64url').slice(0, suffixLength)}`
    if (name.toLowerCase() === targetName.toLowerCase()) {
      continue
    }
    const temp = join(dirname(destination), name)
    try {
      return { temp, file: await open(temp, 'wx', mode) }
    } catch (err) {
      if (!isErrnoException(err) || err.code !== 'EEXIST') {
        throw err
      }
    }
  }
  throw new HostFilesystemError(
    'Could not reserve a publication staging path',
    destination,
    'EEXIST',
  )
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
        // Private files must have their requested mode from the first write.
        await writeFile(path, content, { mode })
        // chmod is a no-op on Windows; skip to avoid errors
        if (osPlatform() !== 'win32') {
          await chmod(path, mode)
        }
      } catch (err) {
        throw toHostFilesystemError(err, path)
      }
    },

    async writeFileIfAbsent(path: string, content: Uint8Array, mode: number): Promise<boolean> {
      const dir = dirname(path)
      let stage: Awaited<ReturnType<typeof openPublicationStage>>
      try {
        await mkdir(dir, { recursive: true, mode: 0o700 })
        stage = await openPublicationStage(path, mode)
      } catch (err) {
        throw toHostFilesystemError(err, path)
      }
      const { temp, file } = stage
      try {
        try {
          await file.writeFile(content)
          if (osPlatform() !== 'win32') await file.chmod(mode)
        } catch (err) {
          await file.close().catch(() => undefined)
          throw err
        }
        await file.close()
        try {
          await link(temp, path)
        } catch (err) {
          if (isErrnoException(err)) {
            if (err.code === 'EEXIST') return false
            // A filesystem can refuse a hard link while allowing a rename.
            // libuv maps the Windows exFAT link failure to EISDIR.
            if (
              err.code === 'ENOTSUP' ||
              err.code === 'EOPNOTSUPP' ||
              err.code === 'ENOSYS' ||
              err.code === 'EPERM' ||
              (process.platform === 'win32' && err.code === 'EISDIR')
            ) {
              throw new LockingNotSupportedError(
                `Cannot atomically publish ${path}: ${err.message}`,
              )
            }
          }
          throw err
        }
        return true
      } catch (err) {
        if (err instanceof LockingNotSupportedError) throw err
        throw toHostFilesystemError(err, path)
      } finally {
        await unlink(temp).catch(() => undefined)
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

    async listDir(
      path: string,
      lowercaseLookup = false,
      include?: (name: string) => boolean,
    ): Promise<string[]> {
      if (!lowercaseLookup) {
        // Ordinary Node host consumers have always received an empty list on errors.
        return readdir(path).catch(() => [])
      }
      try {
        const entries = await readdir(path, { withFileTypes: true })
        const names = new Set<string>()
        for (const entry of entries) {
          if (!entry.isFile() && !entry.isSymbolicLink()) {
            continue
          }
          const canonical = entry.name.replace(/[A-Z]/g, (letter) => letter.toLowerCase())
          // Unrelated links must not participate in record lookup or its failure modes.
          if (include !== undefined && !include(canonical)) {
            continue
          }
          if (entry.isFile() && canonical === entry.name) {
            names.add(canonical)
            continue
          }
          // Probe the path the core will open rather than assuming case folding.
          const candidate = join(path, canonical)
          try {
            if ((await stat(candidate)).isFile()) {
              names.add(canonical)
            }
          } catch (err) {
            if (
              !isErrnoException(err) ||
              (err.code !== 'ENOENT' && err.code !== 'ENOTDIR' && err.code !== 'ELOOP')
            ) {
              throw toHostFilesystemError(err, candidate)
            }
          }
        }
        return [...names]
      } catch (err) {
        if (err instanceof HostFilesystemError) {
          throw err
        }
        if (isErrnoException(err) && err.code === 'ENOENT') {
          return []
        }
        throw toHostFilesystemError(err, path)
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

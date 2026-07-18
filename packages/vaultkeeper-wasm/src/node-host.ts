/**
 * Node.js implementation of WasmHostPlatform.
 *
 * Bridges Node.js file I/O and child_process to the WASM module's
 * expected host platform interface.
 */

import { execFile } from 'node:child_process'
import {
  access,
  mkdir,
  readdir,
  readFile,
  rename,
  unlink,
  writeFile,
  chmod,
} from 'node:fs/promises'
import { homedir, platform as osPlatform } from 'node:os'
import { dirname, join } from 'node:path'
import type { WasmHostPlatform } from './types.js'

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
      stdin?: Uint8Array,
    ): Promise<{ stdout: Uint8Array; stderr: Uint8Array; exitCode: number }> {
      return new Promise((resolve) => {
        const child = execFile(cmd, args, { encoding: 'buffer' }, (error, stdout, stderr) => {
          resolve({
            stdout: new Uint8Array(stdout),
            stderr: new Uint8Array(stderr),
            exitCode:
              error?.code !== undefined ? (typeof error.code === 'number' ? error.code : 1) : 0,
          })
        })

        if (stdin !== undefined && child.stdin) {
          child.stdin.write(stdin)
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
        await writeFile(path, content)
        // chmod is a no-op on Windows; skip to avoid errors
        if (osPlatform() !== 'win32') {
          await chmod(path, mode)
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

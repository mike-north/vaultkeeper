/**
 * Node.js implementation of WasmHostPlatform.
 *
 * Bridges Node.js file I/O and child_process to the WASM module's
 * expected host platform interface.
 */

import { execFile } from 'node:child_process';
import { access, mkdir, readdir, readFile, unlink, writeFile, chmod } from 'node:fs/promises';
import { homedir, platform as osPlatform } from 'node:os';
import { dirname, join } from 'node:path';
import type { WasmHostPlatform } from './types.js';

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
  const configDir = configDirOverride ?? resolveConfigDir();

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
            exitCode: error?.code !== undefined ? (typeof error.code === 'number' ? error.code : 1) : 0,
          });
        });

        if (stdin !== undefined && child.stdin) {
          child.stdin.write(stdin);
          child.stdin.end();
        }
      });
    },

    async readFile(path: string): Promise<Uint8Array> {
      const buf = await readFile(path);
      return new Uint8Array(buf);
    },

    async writeFile(path: string, content: Uint8Array, mode: number): Promise<void> {
      // Ensure parent directory exists (use path.dirname for cross-platform support)
      const dir = dirname(path);
      if (dir && dir !== '.') {
        await mkdir(dir, { recursive: true });
      }
      await writeFile(path, content);
      // chmod is a no-op on Windows; skip to avoid errors
      if (osPlatform() !== 'win32') {
        await chmod(path, mode);
      }
    },

    async fileExists(path: string): Promise<boolean> {
      try {
        await access(path);
        return true;
      } catch {
        return false;
      }
    },

    async deleteFile(path: string): Promise<void> {
      await unlink(path);
    },

    async listDir(path: string): Promise<string[]> {
      try {
        return await readdir(path);
      } catch {
        return [];
      }
    },

    platform(): string {
      const p = osPlatform();
      if (p === 'darwin') return 'darwin';
      if (p === 'win32') return 'win32';
      return 'linux';
    },

    configDir(): string {
      return configDir;
    },
  };
}

function resolveConfigDir(): string {
  const envDir = process.env.VAULTKEEPER_CONFIG_DIR;
  if (envDir) return envDir;

  const p = osPlatform();
  const home = homedir();
  if (p === 'win32') return join(process.env.APPDATA ?? join(home, 'AppData', 'Roaming'), 'vaultkeeper');
  // macOS and Linux both use ~/.config/vaultkeeper (matching the TS SDK)
  return join(home, '.config', 'vaultkeeper');
}

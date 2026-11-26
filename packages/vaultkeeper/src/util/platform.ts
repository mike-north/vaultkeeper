/**
 * Platform detection utilities.
 */

import { SetupError } from '../errors.js'

/**
 * The OS platform identifier used for platform-specific behavior.
 * @public
 */
export type Platform = 'darwin' | 'win32' | 'linux'

/**
 * Get the current platform.
 * @throws {SetupError} If `process.platform` is not one of the three
 * supported platforms.
 */
export function currentPlatform(): Platform {
  const p = process.platform
  if (p === 'darwin' || p === 'win32' || p === 'linux') {
    return p
  }
  throw new SetupError(`Unsupported platform: ${p}`, 'platform')
}

/** Check if running on macOS. */
export function isDarwin(): boolean {
  return process.platform === 'darwin'
}

/** Check if running on Windows. */
export function isWindows(): boolean {
  return process.platform === 'win32'
}

/** Check if running on Linux. */
export function isLinux(): boolean {
  return process.platform === 'linux'
}

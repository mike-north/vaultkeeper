/**
 * Interactive setup discovery for the macOS Keychain backend.
 *
 * @internal
 */

import { execCommand } from '../../util/exec.js'
import { SetupError } from '../../errors.js'
import type { SetupChoice, SetupQuestion, SetupResult } from '../setup-types.js'

/**
 * Parses one line from `security list-keychains` output.
 * Each line is of the form:
 *   `    "/path/to/some.keychain-db"`
 * Returns the unquoted path, or `undefined` if the line cannot be parsed.
 */
function parseKeychainLine(line: string): string | undefined {
  const trimmed = line.trim()
  if (!trimmed.startsWith('"') || !trimmed.endsWith('"')) {
    return undefined
  }
  return trimmed.slice(1, -1)
}

/**
 * Derives a human-friendly display name from a full keychain path.
 * Given `/Users/foo/Library/Keychains/login.keychain-db` returns `login`.
 */
function keychainDisplayName(fullPath: string): string {
  const filename = fullPath.split('/').at(-1) ?? fullPath
  // Strip everything from the first dot onward (e.g. ".keychain-db")
  const dotIndex = filename.indexOf('.')
  return dotIndex === -1 ? filename : filename.slice(0, dotIndex)
}

/**
 * Lists all keychains registered with the macOS `security` tool.
 *
 * Runs `security list-keychains` and returns one {@link SetupChoice} per
 * keychain, where `value` is the absolute path and `label` is a friendly
 * display name derived from the filename.
 *
 * @throws Errors from `execCommand` propagate if the `security` tool is
 *   unavailable or fails.
 * @internal
 */
export async function listKeychains(): Promise<SetupChoice[]> {
  const output = await execCommand('security', ['list-keychains'])

  const choices: SetupChoice[] = []
  for (const line of output.split('\n')) {
    if (line.trim() === '') {
      continue
    }
    const path = parseKeychainLine(line)
    if (path !== undefined) {
      choices.push({ value: path, label: keychainDisplayName(path) })
    }
  }
  return choices
}

/**
 * Creates a setup generator for the macOS Keychain backend.
 *
 * Behaviour:
 * - If no keychains are found, throws {@link SetupError}.
 * - If exactly one keychain is found, auto-selects it without prompting.
 * - If multiple keychains are found, yields a selection question and waits
 *   for the caller to send the chosen keychain path back via `generator.next(value)`.
 *
 * Returns a {@link SetupResult} whose `options.keychain` is the path of the
 * selected keychain.
 *
 * @internal
 */
export async function* createKeychainSetup(): AsyncGenerator<SetupQuestion, SetupResult, string> {
  const keychains = await listKeychains()

  if (keychains.length === 0) {
    throw new SetupError(
      'No keychains found. Ensure that macOS Keychain is available and at least one keychain is registered.',
      'macOS Keychain',
    )
  }

  if (keychains.length === 1) {
    // Array#at(0) returns T | undefined (unlike index access with noUncheckedIndexedAccess,
    // which is also T | undefined). We use at() here to make the undefined guard explicit
    // and recognisable to ESLint's no-unnecessary-condition rule.
    const selected = keychains.at(0)
    if (selected === undefined) {
      throw new SetupError('Unexpected empty keychain list', 'macOS Keychain')
    }
    return { options: { keychain: selected.value } }
  }

  const question: SetupQuestion = {
    key: 'keychain',
    prompt: 'Select a keychain',
    choices: keychains,
  }

  const selectedKeychain = yield question

  return { options: { keychain: selectedKeychain } }
}

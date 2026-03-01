/**
 * Interactive setup discovery for the 1Password backend.
 *
 * @internal
 */

import { execCommand } from '../../util/exec.js'
import { SetupError } from '../../errors.js'
import type { SetupChoice, SetupQuestion, SetupResult } from '../setup-types.js'

/** Minimum shape we expect from `op account list --format=json`. */
interface OpAccountListEntry {
  account_uuid: string
  url: string
  email: string
}

/** Minimum shape we expect from `op account get --format=json`. */
interface OpAccountGetEntry {
  name: string
}

/** Minimum shape we expect from `op vault list --format=json`. */
interface OpVaultListEntry {
  id: string
  name: string
}

const RETRY_COUNT = 2
const RETRY_DELAY_MS = 500

function isOpAccountListEntry(value: unknown): value is OpAccountListEntry {
  if (typeof value !== 'object' || value === null) return false
  return (
    'account_uuid' in value &&
    typeof value.account_uuid === 'string' &&
    'url' in value &&
    typeof value.url === 'string' &&
    'email' in value &&
    typeof value.email === 'string'
  )
}

function isOpAccountGetEntry(value: unknown): value is OpAccountGetEntry {
  if (typeof value !== 'object' || value === null) return false
  return 'name' in value && typeof value.name === 'string'
}

function isOpVaultListEntry(value: unknown): value is OpVaultListEntry {
  if (typeof value !== 'object' || value === null) return false
  return (
    'id' in value &&
    typeof value.id === 'string' &&
    'name' in value &&
    typeof value.name === 'string'
  )
}

function parseJsonArray<T>(
  json: string,
  guard: (v: unknown) => v is T,
): T[] {
  const parsed: unknown = JSON.parse(json)
  if (!Array.isArray(parsed)) return []
  return parsed.filter(guard)
}

async function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function execWithRetry(
  command: string,
  args: string[],
  retries: number,
  delayMs: number,
): Promise<string> {
  let lastError: unknown
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await execCommand(command, args)
    } catch (err) {
      lastError = err
      if (attempt < retries) {
        await delay(delayMs)
      }
    }
  }
  throw lastError
}

/**
 * Lists all 1Password accounts available via the `op` CLI.
 *
 * Runs `op account list --format=json` and, for each account, fetches its
 * full name via `op account get`. Returns one {@link SetupChoice} per account
 * where `value` is the `account_uuid` and `label` is `"name (email)"`.
 *
 * Implements retry logic: up to 2 retries (3 total attempts) with a 500 ms delay on failure.
 * Returns an empty array if the `op` CLI fails after all retries.
 *
 * @internal
 */
export async function listAccounts(): Promise<SetupChoice[]> {
  let listJson: string
  try {
    listJson = await execWithRetry('op', ['account', 'list', '--format=json'], RETRY_COUNT, RETRY_DELAY_MS)
  } catch {
    return []
  }

  let accounts: OpAccountListEntry[]
  try {
    accounts = parseJsonArray(listJson, isOpAccountListEntry)
  } catch {
    return []
  }

  const choices: SetupChoice[] = []
  for (const account of accounts) {
    let label = account.email
    try {
      const getJson = await execWithRetry(
        'op',
        ['account', 'get', '--account', account.account_uuid, '--format=json'],
        RETRY_COUNT,
        RETRY_DELAY_MS,
      )
      // `op account get` returns a single JSON object, not an array;
      // wrap it so parseJsonArray can process it uniformly.
      const detail = parseJsonArray(`[${getJson}]`, isOpAccountGetEntry)
      const entry = detail[0]
      if (entry !== undefined) {
        label = `${entry.name} (${account.email})`
      }
    } catch {
      // Fall back to email-only label if detail fetch fails
    }
    choices.push({ value: account.account_uuid, label })
  }

  return choices
}

/**
 * Lists all vaults in the given 1Password account.
 *
 * Runs `op vault list --account <uuid> --format=json` and returns one
 * {@link SetupChoice} per vault where `value` is the vault `id` and `label`
 * is the vault `name`.
 *
 * @internal
 */
export async function listVaults(accountUuid: string): Promise<SetupChoice[]> {
  let json: string
  try {
    json = await execCommand('op', ['vault', 'list', '--account', accountUuid, '--format=json'])
  } catch {
    return []
  }

  let vaults: OpVaultListEntry[]
  try {
    vaults = parseJsonArray(json, isOpVaultListEntry)
  } catch {
    return []
  }

  return vaults.map((v) => ({ value: v.id, label: v.name }))
}

/**
 * Creates a setup generator for the 1Password backend.
 *
 * Behaviour:
 * - If no accounts are found, throws {@link SetupError}.
 * - If exactly one account is found, auto-selects it without prompting.
 * - If multiple accounts are found, yields an account selection question.
 * - If no vaults are found in the selected account, throws {@link SetupError}.
 * - If exactly one vault is found, auto-selects it without prompting.
 * - If multiple vaults are found, yields a vault selection question.
 *
 * Returns a {@link SetupResult} whose `options` contains `account` and `vault`.
 *
 * @internal
 */
export async function* createOnePasswordSetup(): AsyncGenerator<SetupQuestion, SetupResult, string> {
  const accounts = await listAccounts()

  if (accounts.length === 0) {
    throw new SetupError(
      'No 1Password accounts found. Ensure that the `op` CLI is installed and you are signed in.',
      '1Password CLI (op)',
    )
  }

  let selectedAccount: string
  if (accounts.length === 1) {
    // Array#at(0) returns T | undefined. The undefined guard is unreachable at
    // runtime (length === 1 guarantees an element) but satisfies the type system.
    const only = accounts.at(0)
    if (only === undefined) throw new SetupError('Unexpected empty account list', '1Password CLI (op)')
    selectedAccount = only.value
  } else {
    const accountQuestion: SetupQuestion = {
      key: 'account',
      prompt: 'Select a 1Password account',
      choices: accounts,
    }
    selectedAccount = yield accountQuestion
  }

  const vaults = await listVaults(selectedAccount)

  if (vaults.length === 0) {
    throw new SetupError(
      `No vaults found in the selected 1Password account (${selectedAccount}). Ensure the account has at least one vault.`,
      '1Password vault',
    )
  }

  let selectedVault: string
  if (vaults.length === 1) {
    // Array#at(0) returns T | undefined. The undefined guard is unreachable at
    // runtime (length === 1 guarantees an element) but satisfies the type system.
    const only = vaults.at(0)
    if (only === undefined) throw new SetupError('Unexpected empty vault list', '1Password vault')
    selectedVault = only.value
  } else {
    const vaultQuestion: SetupQuestion = {
      key: 'vault',
      prompt: 'Select a vault',
      choices: vaults,
    }
    selectedVault = yield vaultQuestion
  }

  return { options: { account: selectedAccount, vault: selectedVault } }
}

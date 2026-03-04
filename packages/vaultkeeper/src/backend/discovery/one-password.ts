/**
 * Interactive setup discovery for the 1Password backend.
 *
 * @internal
 */

import { createClient, DesktopAuth } from '@1password/sdk'
import type { Client, VaultOverview } from '@1password/sdk'
import { SetupError } from '../../errors.js'
import type { SetupChoice, SetupQuestion, SetupResult } from '../setup-types.js'
import { INTEGRATION_NAME, getIntegrationVersion } from '../one-password-constants.js'

async function createSdkClient(accountName: string): Promise<Client> {
  try {
    return await createClient({
      auth: new DesktopAuth(accountName),
      integrationName: INTEGRATION_NAME,
      integrationVersion: getIntegrationVersion(),
    })
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new SetupError(
      `Could not connect to 1Password for account "${accountName}": ${detail}`,
      '1Password SDK',
    )
  }
}

async function listVaultsFromClient(client: Client): Promise<VaultOverview[]> {
  try {
    return await client.vaults.list()
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new SetupError(
      `Could not list vaults from 1Password: ${detail}`,
      '1Password SDK',
    )
  }
}

/**
 * Creates a setup generator for the 1Password backend.
 *
 * Behaviour:
 * - Asks for an account name (free-form string input).
 * - Creates a temporary SDK client using `DesktopAuth`, triggering biometric
 *   authentication.
 * - If SDK client creation fails, throws {@link SetupError}.
 * - Lists vaults via the SDK. If vault listing fails, throws {@link SetupError}.
 * - If no vaults are found, throws {@link SetupError}.
 * - If exactly one vault is found, auto-selects it without prompting.
 * - If multiple vaults are found, yields a vault selection question.
 * - Yields an access mode question.
 *
 * Returns a {@link SetupResult} whose `options` contains `account`, `vault`,
 * and `accessMode`.
 *
 * @internal
 */
export async function* createOnePasswordSetup(): AsyncGenerator<SetupQuestion, SetupResult, string> {
  const accountQuestion: SetupQuestion = {
    key: 'account',
    prompt: 'Enter your 1Password account name',
  }
  const accountName = yield accountQuestion

  if (accountName.trim() === '') {
    throw new SetupError('Account name cannot be empty', '1Password SDK')
  }

  const client = await createSdkClient(accountName)
  const vaultOverviews = await listVaultsFromClient(client)

  if (vaultOverviews.length === 0) {
    throw new SetupError(
      `No vaults found in the 1Password account "${accountName}". Ensure the account has at least one vault.`,
      '1Password SDK',
    )
  }

  const vaultChoices: SetupChoice[] = vaultOverviews.map((v) => ({
    value: v.id,
    label: v.title,
  }))

  let selectedVault: string
  if (vaultChoices.length === 1) {
    // Array#at(0) returns T | undefined. The undefined guard is unreachable at
    // runtime (length === 1 guarantees an element) but satisfies the type system.
    const only = vaultChoices.at(0)
    if (only === undefined) throw new SetupError('Unexpected empty vault list', '1Password SDK')
    selectedVault = only.value
  } else {
    const vaultQuestion: SetupQuestion = {
      key: 'vault',
      prompt: 'Select a vault',
      choices: vaultChoices,
    }
    selectedVault = yield vaultQuestion
  }

  const accessModeQuestion: SetupQuestion = {
    key: 'accessMode',
    prompt: 'How should secrets be accessed?',
    choices: [
      { value: 'session', label: 'Session (one prompt per session)' },
      { value: 'per-access', label: 'Per-access (prompt for every retrieval)' },
    ],
  }
  const accessMode = yield accessModeQuestion

  return { options: { account: accountName, vault: selectedVault, accessMode } }
}

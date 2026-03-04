/**
 * Per-access worker script for the 1Password SDK backend.
 *
 * @remarks
 * This script is spawned as a child process by `OnePasswordBackend` when
 * `accessMode` is set to `'per-access'`. It creates a fresh SDK client
 * (which triggers a biometric prompt via the desktop app), retrieves a single
 * secret, writes the result to stdout as JSON, then exits immediately.
 *
 * argv layout:
 *   node one-password-worker.js <accountName> <vaultId> <secretId>
 *
 * stdout on success: `{ "value": "<secret>" }`
 * stdout on failure: `{ "error": "<message>", "code": "<code>" }`
 */

import { createClient, DesktopAuth, DesktopSessionExpiredError } from '@1password/sdk'

const TAG = 'vaultkeeper'
const PASSWORD_FIELD_TITLE = 'password'
import { INTEGRATION_NAME, getIntegrationVersion } from './one-password-constants.js'

interface SuccessResponse {
  value: string
}

interface FailureResponse {
  error: string
  code: string
}

function writeSuccess(value: string): void {
  const response: SuccessResponse = { value }
  process.stdout.write(JSON.stringify(response))
}

function writeFailure(error: string, code: string): void {
  const response: FailureResponse = { error, code }
  process.stdout.write(JSON.stringify(response))
}

async function main(): Promise<void> {
  const [, , accountName, vaultId, secretId] = process.argv

  if (accountName === undefined || vaultId === undefined || secretId === undefined) {
    writeFailure('Worker invoked with missing arguments', 'INTERNAL')
    process.exit(1)
  }

  let client
  try {
    client = await createClient({
      auth: new DesktopAuth(accountName),
      integrationName: INTEGRATION_NAME,
      integrationVersion: getIntegrationVersion(),
    })
  } catch (err) {
    if (err instanceof DesktopSessionExpiredError) {
      writeFailure('1Password session has expired', 'LOCKED')
    } else {
      writeFailure(`Authentication failed: ${String(err)}`, 'AUTH_DENIED')
    }
    process.exit(1)
  }

  let overviews
  try {
    overviews = await client.items.list(vaultId)
  } catch (err) {
    writeFailure(`Failed to list items: ${String(err)}`, 'INTERNAL')
    process.exit(1)
  }

  let targetId: string | undefined
  for (const overview of overviews) {
    if (overview.title === secretId && overview.tags.includes(TAG)) {
      targetId = overview.id
      break
    }
  }

  if (targetId === undefined) {
    writeFailure(`Secret not found: ${secretId}`, 'NOT_FOUND')
    process.exit(1)
  }

  let item
  try {
    item = await client.items.get(vaultId, targetId)
  } catch (err) {
    writeFailure(`Failed to retrieve item: ${String(err)}`, 'NOT_FOUND')
    process.exit(1)
  }

  let secretValue: string | undefined
  for (const field of item.fields) {
    if (field.title === PASSWORD_FIELD_TITLE) {
      secretValue = field.value
      break
    }
  }

  if (secretValue === undefined) {
    writeFailure(`Item found but missing password field: ${secretId}`, 'NOT_FOUND')
    process.exit(1)
  }

  writeSuccess(secretValue)
}

main().catch((err: unknown) => {
  writeFailure(`Unexpected worker error: ${String(err)}`, 'INTERNAL')
  process.exit(1)
})

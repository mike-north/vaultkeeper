/**
 * Shared 1Password item read/write operations.
 *
 * @remarks
 * Both `OnePasswordBackend` (session client) and `one-password-worker.ts` (the
 * per-access worker process spawned for a fresh biometric approval) look items
 * up by title the same way, and must create-or-update / delete a
 * `Password`-category item identically — see issue #211. Centralising that
 * logic here keeps the two call sites from diverging.
 *
 * All SDK types are imported `import type` only, so this module carries no
 * runtime dependency on `@1password/sdk` and stays lazy-load-safe like the
 * rest of the 1Password integration: callers pass in an already-created
 * `Client` plus the SDK's own `ItemCategory`/`ItemFieldType` enum members
 * (obtained from their own dynamically-loaded SDK instance).
 *
 * @internal
 */

import type { Client, Item, ItemOverview, ItemCategory, ItemFieldType } from '@1password/sdk'

/** Tag applied to every item vaultkeeper manages, used to scope list/find calls. */
export const TAG = 'vaultkeeper'

/** Title of the field that carries the secret value. */
export const PASSWORD_FIELD_TITLE = 'password'

/**
 * List all items in the vault tagged "vaultkeeper" and find one with the
 * matching title (= secret ID). Returns `undefined` if not found.
 */
export async function findItemOverviewByTitle(
  client: Client,
  vaultId: string,
  title: string,
): Promise<ItemOverview | undefined> {
  const overviews = await client.items.list(vaultId)
  for (const overview of overviews) {
    if (overview.title === title && overview.tags.includes(TAG)) {
      return overview
    }
  }
  return undefined
}

/**
 * Fetch the full item for a given secret id. Returns `undefined` if not found.
 */
export async function findItemByTitle(
  client: Client,
  vaultId: string,
  title: string,
): Promise<Item | undefined> {
  const overview = await findItemOverviewByTitle(client, vaultId, title)
  if (overview === undefined) return undefined
  return client.items.get(vaultId, overview.id)
}

/**
 * Extract the concealed password field value from an item, or `undefined` if
 * the item has no `password`-titled field.
 */
export function extractPasswordField(item: Item): string | undefined {
  for (const field of item.fields) {
    if (field.title === PASSWORD_FIELD_TITLE) {
      return field.value
    }
  }
  return undefined
}

/**
 * Create-or-update a `Password`-category item's concealed password field.
 *
 * @remarks
 * Updates the existing item's password field (appending one if missing) via
 * `items.put`, or creates a new tagged item via `items.create` when none
 * exists yet under `title`. `passwordCategory`/`concealedFieldType` are the
 * caller's own `ItemCategory.Password` / `ItemFieldType.Concealed` enum
 * members — passed in rather than imported here so this module never needs a
 * value import of the optional `@1password/sdk` peer.
 */
export async function storeSecretItem(
  client: Client,
  vaultId: string,
  title: string,
  secret: string,
  passwordCategory: ItemCategory,
  concealedFieldType: ItemFieldType,
): Promise<void> {
  const existing = await findItemByTitle(client, vaultId, title)

  if (existing !== undefined) {
    const hasPasswordField = existing.fields.some((f) => f.title === PASSWORD_FIELD_TITLE)
    const updatedFields = hasPasswordField
      ? existing.fields.map((f) => (f.title === PASSWORD_FIELD_TITLE ? { ...f, value: secret } : f))
      : [
          ...existing.fields,
          {
            id: 'password',
            title: PASSWORD_FIELD_TITLE,
            fieldType: concealedFieldType,
            value: secret,
          },
        ]
    await client.items.put({ ...existing, fields: updatedFields })
  } else {
    await client.items.create({
      category: passwordCategory,
      vaultId,
      title,
      tags: [TAG],
      fields: [
        {
          id: 'password',
          title: PASSWORD_FIELD_TITLE,
          fieldType: concealedFieldType,
          value: secret,
        },
      ],
    })
  }
}

/**
 * Delete the tagged item matching `title`.
 * @returns `true` if a matching item was found and deleted, `false` if none matched.
 */
export async function deleteSecretItem(
  client: Client,
  vaultId: string,
  title: string,
): Promise<boolean> {
  const overview = await findItemOverviewByTitle(client, vaultId, title)
  if (overview === undefined) return false
  await client.items.delete(vaultId, overview.id)
  return true
}

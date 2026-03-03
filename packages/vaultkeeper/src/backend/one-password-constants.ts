/**
 * Shared constants for 1Password SDK integration.
 *
 * @remarks
 * Centralised here so the backend, worker, and discovery modules stay in sync.
 *
 * @internal
 */

/** Name reported to the 1Password SDK for integration tracking. */
export const INTEGRATION_NAME = 'vaultkeeper'

/**
 * Version reported to the 1Password SDK.
 * Keep in sync with the version in packages/vaultkeeper/package.json.
 */
export const INTEGRATION_VERSION = '1.0.0'

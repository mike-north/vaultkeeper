/**
 * @vaultkeeper/test-helpers — Test utilities for vaultkeeper consumers.
 *
 * @packageDocumentation
 */

export { InMemoryBackend } from './in-memory-backend.js'
export type { InMemoryBackendFaultOperation } from './in-memory-backend.js'
export { FaultPlan } from './fault-plan.js'
export type { FaultMode, FaultOptions } from './fault-plan.js'
export { TestVault } from './test-vault.js'
export type {
  TestVaultOptions,
  TestVaultSetupOptions,
  TestVaultSignCeremonyResult,
} from './test-vault.js'
export { PresenceSimulatorBackend } from './presence-simulator-backend.js'
export type {
  PresenceSimulatorOutcome,
  PresenceSimulatorOperationOutcomes,
  PresenceSimulatorBackendOptions,
} from './presence-simulator-backend.js'

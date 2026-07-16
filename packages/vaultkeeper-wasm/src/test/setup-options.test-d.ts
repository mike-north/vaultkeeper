/**
 * Type-level tests for the WASM SDK's {@link SetupOptions} discriminated union
 * and the {@link VaultKeeper.setup} signature (issue #201).
 *
 * The public contract mirrors the TypeScript `vaultkeeper` library: `setup()`
 * requires the options argument, and it must carry **exactly one** trust choice
 * — either `executablePath` (TOFU verification) or `skipTrust: true`
 * (development opt-out), never both and never neither. These assertions fail the
 * type-check build (`tsc --noEmit`) if that contract ever regresses — e.g. if a
 * 2-arg `setup('X', 'v')` starts compiling again, as it did before this fix.
 *
 * This file is deliberately named `*.test-d.ts` (not `*.test.ts`): it is a
 * compile-time-only fixture validated by `tsc`, and its compiled output is not
 * matched by the `node --test dist/test/*.test.js` runtime glob.
 *
 * @see ../types.ts — SetupOptions / SetupOptionsBase
 * @see ../index.ts — VaultKeeper.setup
 */
import type { SetupOptions, SetupOptionsBase, VaultKeeper } from '../index.js'

declare const vault: VaultKeeper

// --- Valid single-choice forms compile ---------------------------------------

// executablePath alone — the production TOFU choice.
void vault.setup('X', 'v', { executablePath: '/usr/local/bin/my-tool' })
// skipTrust: true alone — the development opt-out.
void vault.setup('X', 'v', { skipTrust: true })
// A trust choice combined with base options is still valid.
void vault.setup('X', 'v', { executablePath: '/usr/local/bin/my-tool', ttlMinutes: 5 })
void vault.setup('X', 'v', { skipTrust: true, useLimit: 3, backendType: 'keychain' })

// --- Invalid forms are type errors -------------------------------------------

// @ts-expect-error — the options argument is required (no 2-arg setup('X', 'v')).
void vault.setup('X', 'v')

// @ts-expect-error — {} satisfies neither branch of the union (missing choice).
void vault.setup('X', 'v', {})

// @ts-expect-error — base-only options still lack the mandatory trust choice.
void vault.setup('X', 'v', { ttlMinutes: 5 })

// @ts-expect-error — executablePath and skipTrust are mutually exclusive.
void vault.setup('X', 'v', { executablePath: '/usr/local/bin/my-tool', skipTrust: true })

// @ts-expect-error — only skipTrust: true is a valid choice; false is not.
void vault.setup('X', 'v', { skipTrust: false })

// --- Structural assertions: base ∧ (executablePath XOR skipTrust) -------------

// Each valid single-choice object is assignable to SetupOptions.
const withExe: SetupOptions = { executablePath: '/usr/local/bin/my-tool' }
const withSkip: SetupOptions = { skipTrust: true }
void withExe
void withSkip

// The common (non-trust) fields live on SetupOptionsBase.
const base: SetupOptionsBase = { ttlMinutes: 5, useLimit: 3, backendType: 'keychain' }
void base

// @ts-expect-error — SetupOptionsBase does not carry the trust-choice fields.
const baseWithChoice: SetupOptionsBase = { executablePath: '/usr/local/bin/my-tool' }
void baseWithChoice

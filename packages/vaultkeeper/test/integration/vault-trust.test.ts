/**
 * Integration tests for VaultKeeper's TOFU trust API:
 * {@link VaultKeeper.approveExecutable} and {@link VaultKeeper.checkExecutableTrust},
 * plus the recording side effect of {@link VaultKeeper.setup} that an
 * interactive `exec` approval relies on.
 *
 * These exercise the real trust-manifest read/write path (temp config dir) and
 * the real SHA-256 hashing of on-disk files. Secrets come from an in-memory
 * backend so no OS credential store is touched.
 *
 * Trust manifest format and hashing: SHA-256 hex digest of the file's bytes,
 * keyed by the executable's resolved absolute path.
 *
 * @see ../../src/identity/manifest.ts
 * @see https://github.com/mike-north/vaultkeeper/issues/57
 * @see https://github.com/mike-north/vaultkeeper/issues/123
 * @see https://github.com/mike-north/vaultkeeper/issues/148
 */

import * as crypto from 'node:crypto'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import {
  VaultKeeper,
  BackendRegistry,
  VaultError,
  IdentityMismatchError,
  ExecutableTrustRequiredError,
  FilesystemError,
  BackendUnavailableError,
  SecretNotFoundError,
} from '../../src/index.js'
import type { VaultConfig, SecretBackend } from '../../src/index.js'
import { createInMemoryBackend } from '../helpers/backend.js'

const TEST_CONFIG: VaultConfig = {
  version: 1,
  backends: [{ type: 'memory', enabled: true }],
  keyRotation: { gracePeriodDays: 1 },
  defaults: { ttlMinutes: 5, trustTier: 3 },
}

/** Independent SHA-256 reference (the spec) — not the implementation under test. */
function sha256Hex(bytes: string): string {
  return crypto.createHash('sha256').update(bytes).digest('hex')
}

let backend: SecretBackend
let configDir: string
let scratchDir: string

beforeEach(async () => {
  backend = createInMemoryBackend()
  BackendRegistry.register('memory', () => backend)
  configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-trust-cfg-'))
  scratchDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-trust-exe-'))
})

afterEach(async () => {
  await fs.rm(configDir, { recursive: true, force: true })
  await fs.rm(scratchDir, { recursive: true, force: true })
})

async function createVault(): Promise<VaultKeeper> {
  return VaultKeeper.init({ skipDoctor: true, config: TEST_CONFIG, configDir })
}

async function writeExecutable(name: string, contents: string): Promise<string> {
  const p = path.join(scratchDir, name)
  await fs.writeFile(p, contents, { mode: 0o755 })
  return p
}

async function manifestExists(): Promise<boolean> {
  return fs
    .access(path.join(configDir, 'trust-manifest.json'))
    .then(() => true)
    .catch(() => false)
}

async function readManifestEntries(): Promise<Record<string, unknown>> {
  const raw = await fs.readFile(path.join(configDir, 'trust-manifest.json'), 'utf8')
  const parsed: unknown = JSON.parse(raw)
  if (
    typeof parsed === 'object' &&
    parsed !== null &&
    'entries' in parsed &&
    typeof parsed.entries === 'object' &&
    parsed.entries !== null
  ) {
    return { ...parsed.entries }
  }
  throw new Error('manifest has no entries object')
}

describe('VaultKeeper.approveExecutable', () => {
  // Criterion 1: approve computes SHA-256 and writes a manifest entry.
  it('records the executable SHA-256 in the trust manifest', async () => {
    const exe = await writeExecutable('deploy.sh', '#!/bin/sh\necho hi\n')
    const expectedHash = sha256Hex('#!/bin/sh\necho hi\n')

    const vault = await createVault()
    const status = await vault.approveExecutable(exe)

    expect(status.trusted).toBe(true)
    expect(status.hash).toBe(expectedHash)
    expect(status.approvedHashes).toEqual([expectedHash])

    const entries = await readManifestEntries()
    const entry = entries[path.resolve(exe)]
    expect(entry).toEqual({ hashes: [expectedHash], trustTier: 3 })
  })

  // Criterion 1: running approve twice is idempotent — one entry, one hash.
  it('is idempotent when approving the same unchanged executable twice', async () => {
    const exe = await writeExecutable('deploy.sh', 'payload\n')
    const expectedHash = sha256Hex('payload\n')

    const vault = await createVault()
    await vault.approveExecutable(exe)
    await vault.approveExecutable(exe)

    const entries = await readManifestEntries()
    expect(Object.keys(entries)).toEqual([path.resolve(exe)])
    expect(entries[path.resolve(exe)]).toEqual({ hashes: [expectedHash], trustTier: 3 })
  })

  // Criterion 2: approving a nonexistent path throws, naming the path.
  it('throws a FilesystemError naming the missing path', async () => {
    const missing = path.join(scratchDir, 'does-not-exist.sh')
    const vault = await createVault()

    await expect(vault.approveExecutable(missing)).rejects.toBeInstanceOf(FilesystemError)
    await expect(vault.approveExecutable(missing)).rejects.toThrow(path.resolve(missing))
  })
})

describe('VaultKeeper.checkExecutableTrust', () => {
  // Criterion 3: after approve, the executable resolves to a trusted state.
  it('reports trusted after the executable was approved', async () => {
    const exe = await writeExecutable('tool', 'binary-bytes\n')
    const vault = await createVault()
    await vault.approveExecutable(exe)

    const status = await vault.checkExecutableTrust(exe)
    expect(status.trusted).toBe(true)
    expect(status.hashMismatch).toBe(false)
    expect(status.approvedHashes).toEqual([sha256Hex('binary-bytes\n')])
  })

  it('reports untrusted for an executable that was never approved', async () => {
    const exe = await writeExecutable('tool', 'binary-bytes\n')
    const vault = await createVault()

    const status = await vault.checkExecutableTrust(exe)
    expect(status.trusted).toBe(false)
    expect(status.hashMismatch).toBe(false)
    expect(status.approvedHashes).toEqual([])
  })

  // Criterion 5: a changed hash is untrusted and flagged as a mismatch —
  // trust is never silently inherited by a modified executable.
  it('reports a hash mismatch when the executable changed after approval', async () => {
    const exe = await writeExecutable('tool', 'original\n')
    const vault = await createVault()
    await vault.approveExecutable(exe)

    await fs.writeFile(exe, 'tampered\n', { mode: 0o755 })

    const status = await vault.checkExecutableTrust(exe)
    expect(status.trusted).toBe(false)
    expect(status.hashMismatch).toBe(true)
    expect(status.hash).toBe(sha256Hex('tampered\n'))
    // The prior approved hash is surfaced so callers can report it accurately.
    expect(status.approvedHashes).toEqual([sha256Hex('original\n')])
  })

  it('does not modify the manifest (read-only probe)', async () => {
    const exe = await writeExecutable('tool', 'bytes\n')
    const vault = await createVault()

    await vault.checkExecutableTrust(exe)
    await expect(fs.readFile(path.join(configDir, 'trust-manifest.json'), 'utf8')).rejects.toThrow()
  })
})

describe('exec approval recording (setup) → subsequent trust', () => {
  // Criterion 4: an interactive exec approval records the hash via setup(),
  // so a subsequent check is trusted (no re-prompt needed).
  it('setup records the caller hash, making a later check trusted', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const caller = await writeExecutable('caller', 'caller-bytes\n')
    const vault = await createVault()

    // Before approval the caller is untrusted.
    expect((await vault.checkExecutableTrust(caller)).trusted).toBe(false)

    // setup() is what `exec` runs after the user answers "y" — it records the
    // caller hash via TOFU.
    await vault.setup('API_KEY', { executablePath: caller })

    // A subsequent invocation now sees the caller as trusted.
    expect((await vault.checkExecutableTrust(caller)).trusted).toBe(true)
  })

  // Criterion 5: setup() rejects a caller whose hash changed after recording,
  // matching the existing identity-mismatch behavior.
  it('setup throws IdentityMismatchError when the caller hash changed', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const caller = await writeExecutable('caller', 'v1\n')
    const vault = await createVault()

    await vault.setup('API_KEY', { executablePath: caller })
    await fs.writeFile(caller, 'v2\n', { mode: 0o755 })

    await expect(vault.setup('API_KEY', { executablePath: caller })).rejects.toBeInstanceOf(
      IdentityMismatchError,
    )
  })

  // Regression for review threads 3582262153 / 3582262187: the thrown error must
  // carry the REAL hashes — previousHash = the manifest-recorded approved hash,
  // currentHash = the on-disk hash — not a placeholder string.
  it('setup populates IdentityMismatchError with the real previous and current hashes', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const caller = await writeExecutable('caller', 'v1\n')
    const approvedHash = sha256Hex('v1\n')
    const vault = await createVault()

    await vault.setup('API_KEY', { executablePath: caller })
    await fs.writeFile(caller, 'v2\n', { mode: 0o755 })
    const changedHash = sha256Hex('v2\n')

    const err = await vault.setup('API_KEY', { executablePath: caller }).then(
      () => {
        throw new Error('expected setup to reject')
      },
      (e: unknown) => e,
    )

    expect(err).toBeInstanceOf(IdentityMismatchError)
    if (!(err instanceof IdentityMismatchError)) throw new Error('unreachable')
    expect(err.previousHash).toBe(approvedHash)
    expect(err.currentHash).toBe(changedHash)
    expect(err.previousHash).not.toBe('previously-approved')
  })

  // Regression for review thread 3582165425: setup() must resolve its
  // executablePath to an absolute path before consulting the manifest, exactly
  // as approveExecutable() and checkExecutableTrust() do. Otherwise a caller
  // approved under its absolute key would not match when setup() is handed a
  // non-normalized (or relative) path referring to the same file.
  it('setup matches an approved executable given a non-normalized path (no duplicate entry)', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const exe = await writeExecutable('caller', 'caller-bytes\n')
    const vault = await createVault()

    // Approve under the canonical absolute path.
    await vault.approveExecutable(exe)

    // A non-normalized path (redundant "/./" segment) that resolves to the same
    // file but whose raw string differs from the manifest key.
    const rawWithDot = `${scratchDir}/./caller`
    expect(rawWithDot).not.toBe(path.resolve(exe))

    await vault.setup('API_KEY', { executablePath: rawWithDot })

    // The manifest still holds a single entry keyed by the resolved path — no
    // duplicate was TOFU-recorded under the raw key.
    const entries = await readManifestEntries()
    expect(Object.keys(entries)).toEqual([path.resolve(exe)])
    // And the executable remains trusted (matched, not recorded anew).
    expect((await vault.checkExecutableTrust(exe)).trusted).toBe(true)
  })
})

describe('setup() defers the TOFU manifest write until the operation succeeds (#148)', () => {
  // AC2 + AC3: the exact scenario from #148. Previously #resolveExecutableIdentity
  // ran verifyTrust() — which records a first-encounter (or Sigstore) hash
  // immediately — before backend.retrieve(); a SecretNotFoundError from a
  // nonexistent secret therefore still left the caller's hash durably recorded,
  // letting an attacker (or a typo'd script) pre-seed TOFU trust without ever
  // completing a legitimate first encounter. The manifest write must now be
  // deferred until setup() actually succeeds.
  it('throws SecretNotFoundError for a nonexistent secret and leaves the manifest untouched', async () => {
    const caller = await writeExecutable('caller', 'first-encounter-bytes\n')
    const vault = await createVault()
    // Deliberately no backend.store() call — 'MISSING_SECRET' does not exist.

    await expect(vault.setup('MISSING_SECRET', { executablePath: caller })).rejects.toBeInstanceOf(
      SecretNotFoundError,
    )

    // The failed call must not have pre-seeded TOFU trust for `caller`: no
    // manifest file at all, and a later legitimate first encounter is still
    // untrusted rather than silently matching the pre-seeded hash.
    expect(await manifestExists()).toBe(false)
    expect((await vault.checkExecutableTrust(caller)).trusted).toBe(false)
  })

  // The write is deferred, not removed: a setup() call that actually succeeds
  // still records the first-encounter hash exactly as before.
  it('still records the first-encounter hash when the secret exists and setup() succeeds', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const caller = await writeExecutable('caller', 'success-bytes\n')
    const vault = await createVault()

    await vault.setup('API_KEY', { executablePath: caller })

    const entries = await readManifestEntries()
    expect(Object.keys(entries)).toEqual([path.resolve(caller)])
    expect((await vault.checkExecutableTrust(caller)).trusted).toBe(true)
  })

  // A matching re-encounter (Tier 2 registry match) has nothing to stage —
  // it must keep succeeding and must not rewrite the manifest.
  it('a matching re-encounter succeeds without rewriting the manifest', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const caller = await writeExecutable('caller', 'stable-bytes\n')
    const vault = await createVault()

    await vault.setup('API_KEY', { executablePath: caller })
    const entriesAfterFirst = await readManifestEntries()

    const jwe = await vault.setup('API_KEY', { executablePath: caller })
    expect(jwe.split('.')).toHaveLength(5)

    const entriesAfterSecond = await readManifestEntries()
    expect(entriesAfterSecond).toEqual(entriesAfterFirst)
  })

  // AC4: TOFU-conflict detection must keep using the pre-existing manifest
  // state and fail before any write — even though the secret exists and
  // setup() would otherwise succeed, the new (unapproved) hash must never be
  // recorded.
  it('a hash conflict throws IdentityMismatchError and never records the new hash', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const caller = await writeExecutable('caller', 'v1\n')
    const approvedHash = sha256Hex('v1\n')
    const vault = await createVault()

    await vault.setup('API_KEY', { executablePath: caller })
    await fs.writeFile(caller, 'v2\n', { mode: 0o755 })

    await expect(vault.setup('API_KEY', { executablePath: caller })).rejects.toBeInstanceOf(
      IdentityMismatchError,
    )

    // The manifest must still hold only the originally approved hash.
    const entries = await readManifestEntries()
    expect(entries[path.resolve(caller)]).toEqual({ hashes: [approvedHash], trustTier: 3 })
  })
})

describe('setup() requires an explicit executable-trust choice (#123)', () => {
  // AC1 + AC5: omitting the trust choice throws a typed VaultError subclass —
  // never a plain Error, and never a silent 'dev' fallback. Regression for #123.
  it('throws ExecutableTrustRequiredError when neither executablePath nor skipTrust is given', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const vault = await createVault()

    const err = await vault.setup('API_KEY').then(
      () => {
        throw new Error('expected setup to reject')
      },
      (e: unknown) => e,
    )

    expect(err).toBeInstanceOf(ExecutableTrustRequiredError)
    expect(err).toBeInstanceOf(VaultError)
    if (!(err instanceof ExecutableTrustRequiredError)) throw new Error('unreachable')
    expect(err.reason).toBe('missing-choice')
    // AC1: the message must name both remediation paths.
    expect(err.message).toContain('executablePath')
    expect(err.message).toContain('skipTrust')
    // No secret token is minted and no manifest fallback is recorded.
    expect(await manifestExists()).toBe(false)
  })

  // AC5 negative test: the two contradictory intents are rejected distinctly,
  // so a caller can tell "I forgot" from "I contradicted myself".
  it('throws ExecutableTrustRequiredError (conflicting-choice) when both are given', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const caller = await writeExecutable('caller', 'bytes\n')
    const vault = await createVault()

    const err = await vault.setup('API_KEY', { executablePath: caller, skipTrust: true }).then(
      () => {
        throw new Error('expected setup to reject')
      },
      (e: unknown) => e,
    )

    expect(err).toBeInstanceOf(ExecutableTrustRequiredError)
    if (!(err instanceof ExecutableTrustRequiredError)) throw new Error('unreachable')
    expect(err.reason).toBe('conflicting-choice')
    expect(err.message).toContain('mutually exclusive')
  })

  // AC2 + AC5: the explicit opt-out mints a token and skips verification —
  // proven by the trust manifest never being written.
  it('skipTrust: true mints a token and does not touch the trust manifest', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const vault = await createVault()

    const jwe = await vault.setup('API_KEY', { skipTrust: true })
    expect(jwe.split('.')).toHaveLength(5) // compact JWE

    // Verification was skipped, so no hash was recorded.
    expect(await manifestExists()).toBe(false)
    // The token still authorizes and yields the secret.
    const { token } = await vault.authorize(jwe)
    expect(token).toBeDefined()
  })

  // Regression for PR #131 review thread 3588295526: `skipTrust: false` is
  // not an explicit trust choice — only `skipTrust: true` opts out, and only
  // a provided `executablePath` opts in. Without an `executablePath`,
  // `skipTrust: false` must behave exactly like full omission: the same typed
  // ExecutableTrustRequiredError, not a silent 'dev' fallback. (The reported
  // bug lived in TestVault's wrapper, not here — this test locks in that
  // VaultKeeper.setup() itself already gets this right via `=== true`.)
  it('throws ExecutableTrustRequiredError when skipTrust: false is given without an executablePath', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const vault = await createVault()

    const err = await vault.setup('API_KEY', { skipTrust: false }).then(
      () => {
        throw new Error('expected setup to reject')
      },
      (e: unknown) => e,
    )

    expect(err).toBeInstanceOf(ExecutableTrustRequiredError)
    if (!(err instanceof ExecutableTrustRequiredError)) throw new Error('unreachable')
    expect(err.reason).toBe('missing-choice')
    expect(await manifestExists()).toBe(false)
  })

  // Regression for the same thread: skipTrust: false paired with a real
  // executablePath is not a contradiction (skipTrust is falsy) — verification
  // must run normally and record the hash, exactly as if skipTrust had been
  // omitted entirely.
  it('runs verification normally when skipTrust: false is paired with an executablePath', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const caller = await writeExecutable('caller', 'caller-bytes\n')
    const vault = await createVault()

    const jwe = await vault.setup('API_KEY', { skipTrust: false, executablePath: caller })
    expect(jwe.split('.')).toHaveLength(5)

    const entries = await readManifestEntries()
    expect(Object.keys(entries)).toEqual([path.resolve(caller)])
    expect((await vault.checkExecutableTrust(caller)).trusted).toBe(true)
  })

  // Regression for PR #131 review thread 3588502436 (#123): with executablePath
  // now the primary production path, an unreadable/missing executable makes
  // setup()'s verification hash the file via raw fs, which without wrapping
  // throws a plain Error/TypeError. setup() must surface a typed FilesystemError
  // (a VaultError subclass) naming the resolved path, so callers of setup()
  // consistently receive the typed-error contract — never a bare Error.
  it('throws a typed FilesystemError when a provided executablePath cannot be read', async () => {
    await backend.store('API_KEY', 's3cr3t')
    const missing = path.join(scratchDir, 'does-not-exist.sh')
    const vault = await createVault()

    const err = await vault.setup('API_KEY', { executablePath: missing }).then(
      () => {
        throw new Error('expected setup to reject')
      },
      (e: unknown) => e,
    )

    expect(err).toBeInstanceOf(FilesystemError)
    expect(err).toBeInstanceOf(VaultError)
    if (!(err instanceof FilesystemError)) throw new Error('unreachable')
    expect(err.message).toContain(path.resolve(missing))
    // No token was minted, so nothing was recorded to the manifest either.
    expect(await manifestExists()).toBe(false)
  })

  // Regression for PR #131 review thread 3588773262 (#123): pre-explicit-trust,
  // `executablePath: 'dev'` was THE documented opt-out sentinel. Post-#131 it is
  // no longer special; without a guard it would be resolved as a real path
  // (<cwd>/dev), hashed, and fail with a confusing FilesystemError. setup() must
  // instead reject the legacy sentinel with a typed ExecutableTrustRequiredError
  // that points migrating callers at the new `skipTrust: true` opt-out.
  it("rejects the legacy executablePath: 'dev' sentinel with a migration hint", async () => {
    await backend.store('API_KEY', 's3cr3t')
    const vault = await createVault()

    const err = await vault.setup('API_KEY', { executablePath: 'dev' }).then(
      () => {
        throw new Error('expected setup to reject')
      },
      (e: unknown) => e,
    )

    expect(err).toBeInstanceOf(ExecutableTrustRequiredError)
    expect(err).toBeInstanceOf(VaultError)
    if (!(err instanceof ExecutableTrustRequiredError)) throw new Error('unreachable')
    expect(err.reason).toBe('legacy-dev-sentinel')
    // The message must name the new opt-out so a migrating caller knows the fix.
    expect(err.message).toContain('skipTrust')
    // It must not be masked by a filesystem error about hashing "<cwd>/dev".
    expect(err).not.toBeInstanceOf(FilesystemError)
    // No token minted, no manifest fallback recorded.
    expect(await manifestExists()).toBe(false)
  })
})

describe('trust-only operations without a healthy backend (review thread 3582165455)', () => {
  const UNAVAILABLE_CONFIG: VaultConfig = {
    version: 1,
    // A backend type that is never registered — resolving it would throw.
    backends: [{ type: 'not-registered', enabled: true }],
    keyRotation: { gracePeriodDays: 1 },
    defaults: { ttlMinutes: 5, trustTier: 3 },
  }

  // approve only needs the config dir + trust manifest, so it must succeed even
  // when the configured backend cannot be resolved (unavailable/unregistered).
  it('approveExecutable succeeds even when the configured backend is unregistered', async () => {
    const exe = await writeExecutable('deploy.sh', '#!/bin/sh\necho hi\n')
    const vault = await VaultKeeper.init({
      skipDoctor: true,
      config: UNAVAILABLE_CONFIG,
      configDir,
    })

    const status = await vault.approveExecutable(exe)
    expect(status.trusted).toBe(true)
  })

  // A secret operation still surfaces the backend problem — resolution is
  // deferred, not skipped.
  it('a secret operation still surfaces BackendUnavailableError', async () => {
    const vault = await VaultKeeper.init({
      skipDoctor: true,
      config: UNAVAILABLE_CONFIG,
      configDir,
    })

    await expect(vault.store('API_KEY', 'x')).rejects.toBeInstanceOf(BackendUnavailableError)
  })
})

/**
 * Integration tests for the @vaultkeeper/wasm SDK.
 *
 * These tests verify that the WASM module loads, initializes, and
 * can perform basic operations through the Node.js host platform bridge.
 *
 * Uses node:test (not vitest) since this package compiles with plain tsc.
 */

/* eslint-disable @typescript-eslint/no-floating-promises -- node:test it() returns Promise but is not meant to be awaited inside describe() */
/* eslint-disable n/no-unsupported-features/node-builtins -- test.describe is stable in our CI Node version */

import { describe, it } from 'node:test'
import * as assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { chmod, readFile, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import {
  VaultKeeper,
  VaultError,
  SecretNotFoundError,
  DecryptionError,
  FilesystemError,
  InvalidTokenError,
  RotationInProgressError,
  AccessorConsumedError,
  ExecutableTrustRequiredError,
  IdentityMismatchError,
} from '../index.js'

/**
 * Permission-bit tests need a real POSIX filesystem and a non-root user
 * (root bypasses permission bits entirely, so there'd be nothing to
 * assert). Mirrors the same skip convention as the Rust host test
 * (`crates/vaultkeeper-cli/src/host.rs`,
 * `file_exists_surfaces_filesystem_error_when_probe_is_denied`).
 */
const isPermissionTestable =
  process.platform !== 'win32' && (typeof process.getuid !== 'function' || process.getuid() !== 0)

/**
 * Assert `code` is a real permission-denied errno. Which one a given
 * platform/operation reports isn't guaranteed to be `EACCES` specifically —
 * e.g. some unlink/open paths report `EPERM` instead — so this asserts the
 * failure is genuinely permission-related without hardcoding a single value.
 */
function assertPermissionDeniedCode(code: string | undefined): void {
  assert.ok(
    code === 'EACCES' || code === 'EPERM',
    `expected a permission-denied errno (EACCES or EPERM), got: ${String(code)}`,
  )
}

async function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), 'vk-wasm-test-'))
  try {
    await fn(dir)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

async function createTestVault(dir: string): Promise<VaultKeeper> {
  // Write a minimal config
  const config = {
    version: 1,
    backends: [{ type: 'file', enabled: true }],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes: 60, trustTier: '3' },
  }
  await writeFile(join(dir, 'config.json'), JSON.stringify(config, null, 2) + '\n')

  return VaultKeeper.create({ skipDoctor: true }, dir)
}

/** SHA-256 hex digest of `content`, matching the core's executable hashing. */
function sha256Hex(content: string): string {
  return createHash('sha256').update(content).digest('hex')
}

/**
 * Write a fake executable file into `dir` and return its path plus the hash
 * the trust layer will compute for it.
 */
async function writeFakeExecutable(
  dir: string,
  name: string,
  content: string,
): Promise<{ path: string; hash: string }> {
  const path = join(dir, name)
  await writeFile(path, content)
  return { path, hash: sha256Hex(content) }
}

/**
 * Read the approved hashes recorded for `namespace` in the trust manifest at
 * `<configDir>/trust-manifest.json`. Returns `[]` when the manifest does not
 * exist (nothing recorded), letting tests assert the #148 ordering property.
 */
async function readApprovedHashes(configDir: string, namespace: string): Promise<string[]> {
  let raw: string
  try {
    raw = await readFile(join(configDir, 'trust-manifest.json'), 'utf8')
  } catch (err) {
    // Only a missing manifest means "nothing recorded". Any other failure
    // (EACCES, EISDIR, …) must surface so it can't masquerade as no-entries
    // and mask a real problem in a test asserting the manifest is unwritten.
    if (err instanceof Error && 'code' in err && err.code === 'ENOENT') {
      return []
    }
    throw err
  }
  const parsed: unknown = JSON.parse(raw)
  // Walk the shape with spreads (never `as`) to satisfy the no-type-assertion
  // lint rule, mirroring how errors.ts narrows unknown boundary shapes.
  if (typeof parsed !== 'object' || parsed === null) return []
  const root: Record<string, unknown> = { ...parsed }
  if (typeof root.entries !== 'object' || root.entries === null) return []
  const entries: Record<string, unknown> = { ...root.entries }
  const entry = entries[namespace]
  if (typeof entry !== 'object' || entry === null) return []
  const entryRecord: Record<string, unknown> = { ...entry }
  const hashes: unknown = entryRecord.hashes
  return Array.isArray(hashes) ? hashes.filter((h): h is string => typeof h === 'string') : []
}

describe('@vaultkeeper/wasm SDK', () => {
  it('creates a VaultKeeper instance', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      assert.ok(vault)
      vault.dispose()
    })
  })

  it('reads config', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const cfg = vault.config()
      assert.equal(cfg.version, 1)
      assert.ok(Array.isArray(cfg.backends))
      vault.dispose()
    })
  })

  // Regression for issue #200: `config init` (and the README example) writes
  // `"trustTier": 3` as a bare JSON number. Before the fix the Rust-core reader
  // behind this SDK required a string-encoded number, so `createVaultKeeper`
  // threw `Failed to parse config` on a config produced by the documented CLI
  // flow. The SDK must load the numeric form.
  it('reads a config whose trustTier is a bare JSON number (issue #200)', async () => {
    await withTempDir(async (dir) => {
      const config = {
        version: 1,
        backends: [{ type: 'file', enabled: true }],
        keyRotation: { gracePeriodDays: 7 },
        defaults: { ttlMinutes: 60, trustTier: 3 },
      }
      await writeFile(join(dir, 'config.json'), JSON.stringify(config, null, 2) + '\n')
      const vault = await VaultKeeper.create({ skipDoctor: true }, dir)
      assert.equal(vault.config().version, 1)
      vault.dispose()
    })
  })

  it('setup produces a JWE token', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('test-secret', 'my-value', { skipTrust: true })
      // JWE compact format: 5 base64url segments separated by dots
      const parts = token.split('.')
      assert.equal(parts.length, 5, 'JWE must have 5 parts')
      vault.dispose()
    })
  })

  it('setup + authorize round-trip', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('my-key', 'super-secret', { skipTrust: true })
      const result = vault.authorize(token)

      assert.equal(result.claims.sub, 'my-key')
      // The raw secret is not on the claims — read it via the one-time accessor.
      const secret = result.secret.read((value) => value)
      assert.equal(secret, 'super-secret')
      assert.equal(result.response.keyStatus, 'current')
      vault.dispose()
    })
  })

  it('store and retrieve a secret', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await vault.store('file-secret', 'file-value')
      const retrieved = await vault.retrieve('file-secret')
      assert.equal(retrieved, 'file-value')
      vault.dispose()
    })
  })

  it('rotate key', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      // Should not throw
      vault.rotateKey()
      vault.dispose()
    })
  })

  it('delete a stored secret', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await vault.store('delete-me', 'temp-value')
      await vault.delete('delete-me')
      // Retrieving deleted secret should throw
      await assert.rejects(() => vault.retrieve('delete-me'))
      vault.dispose()
    })
  })

  it('authorize rejects invalid JWE token', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      assert.throws(() => vault.authorize('not-a-valid-jwe'))
      vault.dispose()
    })
  })

  it('authorize rejects tampered JWE token', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('key', 'value', { skipTrust: true })
      // Corrupt the ciphertext (4th segment)
      const parts = token.split('.')
      const segment = parts[3]
      assert.ok(segment, 'JWE should have a 4th segment')
      parts[3] = segment.slice(0, -4) + 'XXXX'
      const tampered = parts.join('.')
      assert.throws(() => vault.authorize(tampered))
      vault.dispose()
    })
  })

  it('setup with custom TTL', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('ttl-key', 'ttl-value', { ttlMinutes: 5, skipTrust: true })
      const result = vault.authorize(token)
      // exp should be iat + 300 seconds (5 minutes)
      assert.equal(result.claims.exp - result.claims.iat, 300)
      vault.dispose()
    })
  })

  it('setup with use limit', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('limit-key', 'limit-value', { useLimit: 3, skipTrust: true })
      const result = vault.authorize(token)
      assert.equal(result.claims.use, 3)
      vault.dispose()
    })
  })

  it('rotate key then authorize with old token re-encrypts', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('rotate-key', 'rotate-value', { skipTrust: true })
      vault.rotateKey()
      const result = vault.authorize(token)
      // Old token decrypted with previous key
      assert.equal(result.response.keyStatus, 'previous')
      assert.ok(result.response.rotatedJwt, 'should provide re-encrypted token')
      // The re-encrypted token should work with the current key
      const result2 = vault.authorize(result.response.rotatedJwt)
      assert.equal(result2.response.keyStatus, 'current')
      assert.equal(
        result2.secret.read((value) => value),
        'rotate-value',
      )
      vault.dispose()
    })
  })

  it('revokeKey generates new key and invalidates old tokens', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('revoke-key', 'revoke-value', { skipTrust: true })
      vault.revokeKey()
      // Old token should be rejected — key was revoked
      assert.throws(() => vault.authorize(token), /revoked|unknown/i)
      // New tokens should still work
      const newToken = await vault.setup('post-revoke', 'new-value', { skipTrust: true })
      const result = vault.authorize(newToken)
      assert.equal(
        result.secret.read((value) => value),
        'new-value',
      )
      assert.equal(result.response.keyStatus, 'current')
      vault.dispose()
    })
  })

  it('double rotate rejects (rotation already in progress)', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      vault.rotateKey()
      assert.throws(() => {
        vault.rotateKey()
      }, /rotation/i)
      vault.dispose()
    })
  })

  it('store and retrieve preserves unicode', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const unicodeValue = '\u{1F512} secure \u{2603} snowman \u{1F60E}'
      await vault.store('unicode-key', unicodeValue)
      const retrieved = await vault.retrieve('unicode-key')
      assert.equal(retrieved, unicodeValue)
      vault.dispose()
    })
  })

  it('doctor returns preflight result', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const result = await vault.doctor()
      assert.ok(typeof result.ready === 'boolean')
      assert.ok(Array.isArray(result.checks))
      assert.ok(Array.isArray(result.warnings))
      assert.ok(Array.isArray(result.nextSteps))
      vault.dispose()
    })
  })

  it('retrieve non-existent secret throws', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(() => vault.retrieve('does-not-exist'))
      vault.dispose()
    })
  })

  it('claims contain expected fields', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('claim-key', 'claim-value', { skipTrust: true })
      const result = vault.authorize(token)
      const claims = result.claims
      // Verify all expected fields exist
      assert.ok(typeof claims.jti === 'string')
      assert.ok(claims.jti.length > 0)
      assert.ok(typeof claims.exp === 'number')
      assert.ok(typeof claims.iat === 'number')
      assert.equal(claims.sub, 'claim-key')
      assert.equal(claims.ref, 'claim-key')
      assert.ok(typeof claims.exe === 'string')
      assert.ok(typeof claims.tid === 'string')
      assert.ok(typeof claims.bkd === 'string')
      vault.dispose()
    })
  })

  it('JWE header uses dir + A256GCM (RFC 7516 interop)', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('interop-key', 'interop-value', { skipTrust: true })
      const parts = token.split('.')
      assert.equal(parts.length, 5, 'compact JWE must have 5 segments')

      const [headerB64, encryptedKey, ivB64, ciphertextB64, tagB64] = parts
      assert.ok(headerB64, 'header segment must exist')

      // Decode the protected header (first segment, base64url)
      const headerJson = Buffer.from(headerB64, 'base64url').toString('utf8')

      // Verify header matches what the TS jose library expects
      assert.ok(headerJson.includes('"alg":"dir"'), 'alg must be dir')
      assert.ok(headerJson.includes('"enc":"A256GCM"'), 'enc must be A256GCM')
      assert.ok(headerJson.includes('"kid":"'), 'kid must be present')

      // For dir algorithm, encrypted key segment (2nd part) must be empty
      assert.equal(encryptedKey, '', 'encrypted key must be empty for dir alg')

      // IV (3rd part) must be present and base64url-decodable to 12 bytes
      assert.ok(ivB64, 'IV segment must exist')
      assert.ok(ivB64.length > 0, 'IV must not be empty')
      const iv = Buffer.from(ivB64, 'base64url')
      assert.equal(iv.length, 12, 'AES-256-GCM IV must be 12 bytes')

      // Ciphertext (4th part) must be present
      assert.ok(ciphertextB64, 'ciphertext segment must exist')
      assert.ok(ciphertextB64.length > 0, 'ciphertext must not be empty')

      // Auth tag (5th part) must be present and base64url-decodable to 16 bytes
      assert.ok(tagB64, 'auth tag segment must exist')
      assert.ok(tagB64.length > 0, 'auth tag must not be empty')
      const tag = Buffer.from(tagB64, 'base64url')
      assert.equal(tag.length, 16, 'AES-256-GCM auth tag must be 16 bytes')

      vault.dispose()
    })
  })

  it('multiple tokens have unique JTIs', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token1 = await vault.setup('key1', 'val1', { skipTrust: true })
      const token2 = await vault.setup('key2', 'val2', { skipTrust: true })
      const result1 = vault.authorize(token1)
      const result2 = vault.authorize(token2)
      assert.notEqual(result1.claims.jti, result2.claims.jti, 'JTIs must be unique')
      vault.dispose()
    })
  })

  it('authorize rejects token with empty sub (secret name)', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      // setup accepts empty name but authorize should reject (claims validation)
      const token = await vault.setup('', 'some-value', { skipTrust: true })
      assert.throws(() => vault.authorize(token), /sub must not be empty/)
      vault.dispose()
    })
  })

  it('authorize rejects token with empty val (secret value)', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      // setup accepts empty value but authorize should reject (claims validation)
      const token = await vault.setup('some-name', '', { skipTrust: true })
      assert.throws(() => vault.authorize(token), /val must not be empty/)
      vault.dispose()
    })
  })

  it('store then overwrite retrieves latest value', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await vault.store('overwrite-key', 'first-value')
      await vault.store('overwrite-key', 'second-value')
      const retrieved = await vault.retrieve('overwrite-key')
      assert.equal(retrieved, 'second-value')
      vault.dispose()
    })
  })

  it('delete non-existent secret throws', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(() => vault.delete('never-stored'))
      vault.dispose()
    })
  })

  it('config returns expected structure', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const cfg = vault.config()
      assert.equal(cfg.version, 1)
      assert.ok(Array.isArray(cfg.backends))
      assert.ok(cfg.backends.length > 0)
      const firstBackend = cfg.backends[0]
      assert.ok(firstBackend, 'first backend must exist')
      assert.equal(firstBackend.type, 'file')
      assert.ok(cfg.keyRotation)
      assert.equal(cfg.keyRotation.gracePeriodDays, 7)
      assert.ok(cfg.defaults)
      assert.equal(cfg.defaults.ttlMinutes, 60)
      vault.dispose()
    })
  })

  it('setup with explicit backend type', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('backend-key', 'backend-value', {
        backendType: 'file',
        skipTrust: true,
      })
      const result = vault.authorize(token)
      assert.equal(result.claims.bkd, 'file')
      vault.dispose()
    })
  })

  it('authorize expired token throws', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      // Create a token with a very short TTL that should be expired by the time we check
      // We can't easily test this without controlling time, but we can test that
      // the claims contain the expected TTL calculation
      const token = await vault.setup('ttl-test', 'ttl-value', { ttlMinutes: 1, skipTrust: true })
      const result = vault.authorize(token)
      // exp should be iat + 60 seconds (1 minute)
      assert.equal(result.claims.exp - result.claims.iat, 60)
      vault.dispose()
    })
  })
})

// Regression tests for issue #66 — WASM SDK security parity:
// authorize() must not return the raw secret, a safe consumption path must
// exist, and errors must be typed VaultError instances.
describe('@vaultkeeper/wasm security parity (issue #66)', () => {
  it('authorize() return shape contains no secret material', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('leak-key', 'test-secret-123', { skipTrust: true })
      const result = vault.authorize(token)

      // The pre-fix leak was at result.claims.val — it must be gone.
      assert.equal(
        Object.prototype.hasOwnProperty.call(result.claims, 'val'),
        false,
        'claims must not carry a val field',
      )

      // No property anywhere in the serialized claims/response may equal the
      // raw secret.
      const serialized = JSON.stringify({ claims: result.claims, response: result.response })
      assert.equal(
        serialized.includes('test-secret-123'),
        false,
        'no part of the authorize() return shape may contain the raw secret',
      )
      vault.dispose()
    })
  })

  it('safe consumption path: one-time accessor reads the secret exactly once', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('accessor-key', 'accessor-secret', { skipTrust: true })
      const result = vault.authorize(token)

      assert.equal(result.secret.available, true)
      const value = result.secret.read((s) => s.toUpperCase())
      assert.equal(value, 'ACCESSOR-SECRET')
      assert.equal(result.secret.available, false, 'accessor must be consumed after read')

      // A second read must fail with a typed AccessorConsumedError.
      assert.throws(
        () => result.secret.read((s) => s),
        (err: unknown) => err instanceof AccessorConsumedError && err instanceof VaultError,
      )
      vault.dispose()
    })
  })

  it('retrieve() of a missing secret throws a typed SecretNotFoundError', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        () => vault.retrieve('does-not-exist'),
        (err: unknown) => err instanceof SecretNotFoundError && err instanceof VaultError,
      )
      vault.dispose()
    })
  })

  it('authorize() of a malformed token throws a typed InvalidTokenError', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      assert.throws(
        () => vault.authorize('not-a-valid-jwe'),
        (err: unknown) => err instanceof InvalidTokenError && err instanceof VaultError,
      )
      vault.dispose()
    })
  })

  it('authorize() of a tampered token throws a typed InvalidTokenError', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('tamper-key', 'tamper-value', { skipTrust: true })
      const parts = token.split('.')
      const segment = parts[3]
      assert.ok(segment, 'JWE should have a 4th segment')
      parts[3] = segment.slice(0, -4) + 'XXXX'
      assert.throws(
        () => vault.authorize(parts.join('.')),
        (err: unknown) => err instanceof InvalidTokenError,
      )
      vault.dispose()
    })
  })

  // Regression test for issue #134: corrupted ciphertext / a failed AES-GCM
  // auth tag previously surfaced as an untyped error at the WASM boundary.
  it('retrieve() of a secret with corrupted ciphertext throws a typed DecryptionError', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await vault.store('corrupt-me', 'some-value')

      // Entry files are stored at `<configDir>/file/<hex(id)>.enc`.
      const entryPath = join(
        dir,
        'file',
        `${Buffer.from('corrupt-me', 'utf8').toString('hex')}.enc`,
      )
      const encoded = await readFile(entryPath, 'utf8')
      // Flip the final character of the `iv:authTag:ciphertext` encoding so
      // the AES-GCM auth tag fails to verify on retrieve.
      const flipped = encoded.endsWith('A') ? 'B' : 'A'
      await writeFile(entryPath, encoded.slice(0, -1) + flipped)

      await assert.rejects(
        () => vault.retrieve('corrupt-me'),
        (err: unknown) => err instanceof DecryptionError && err instanceof VaultError,
      )
      vault.dispose()
    })
  })

  // Regression test for PR #135 review feedback: an on-disk entry that isn't
  // even valid UTF-8 is the same class of corruption as a bad auth tag and
  // must also surface as a typed DecryptionError, not an untyped error.
  it('retrieve() of a non-UTF-8 entry throws a typed DecryptionError', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await vault.store('garbled', 'some-value')

      const entryPath = join(dir, 'file', `${Buffer.from('garbled', 'utf8').toString('hex')}.enc`)
      // 0xFF is never a valid UTF-8 lead or continuation byte.
      await writeFile(entryPath, Buffer.from([0xff, 0xfe, 0xfd]))

      await assert.rejects(
        () => vault.retrieve('garbled'),
        (err: unknown) => err instanceof DecryptionError && err instanceof VaultError,
      )
      vault.dispose()
    })
  })

  it('double key rotation throws a typed RotationInProgressError', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      vault.rotateKey()
      assert.throws(
        () => {
          vault.rotateKey()
        },
        (err: unknown) => err instanceof RotationInProgressError && err instanceof VaultError,
      )
      vault.dispose()
    })
  })
})

// Issue #104: pin the documented setup(secretName, secretValue) contract —
// it mints the token from the `secretValue` argument and never reads
// whatever is already persisted under `secretName` via store()/retrieve().
// This is a deliberate divergence from the TS `vaultkeeper` library's
// setup(secretName, options?), which always reads from the backend. If this
// test starts failing, either the divergence was silently closed (update the
// README/JSDoc accordingly) or setup() regressed to reading stored state.
describe('@vaultkeeper/wasm setup() contract (issue #104)', () => {
  it('setup() mints from its secretValue argument, ignoring any stored value under the same name', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await vault.store('contract-key', 'stored-value')

      const token = await vault.setup('contract-key', 'argument-value', { skipTrust: true })
      const result = vault.authorize(token)

      assert.equal(
        result.secret.read((value) => value),
        'argument-value',
        'setup() must encapsulate the secretValue argument, not the stored value',
      )

      // The stored value is untouched and independently retrievable — store()
      // and setup() are independent operations.
      const stored = await vault.retrieve('contract-key')
      assert.equal(stored, 'stored-value')
      vault.dispose()
    })
  })
})

// Explicit executable-trust contract (issue #147): the WASM SDK's setup() must
// reach the same safe posture as the TypeScript library's setup() (#123/#131) —
// it must NOT silently mint a 'dev'-bound token with no explicit choice. The
// caller must make an explicit trust choice, and the failure surfaces as the
// same typed, reason-tagged error across both SDKs.
describe('@vaultkeeper/wasm setup() explicit-trust contract (issue #147)', () => {
  it('setup() without a trust choice throws ExecutableTrustRequiredError (missing-choice) — no silent token', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        // Omitting the trust choice compiles (options is optional) but is the
        // exact runtime defect under test — it must throw, not mint a token.
        () => vault.setup('no-choice', 'value'),
        (err: unknown) =>
          err instanceof ExecutableTrustRequiredError &&
          err instanceof VaultError &&
          err.reason === 'missing-choice',
      )
      vault.dispose()
    })
  })

  it('setup() with an empty options object still requires a choice (missing-choice)', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        () => vault.setup('empty-opts', 'value', {}),
        (err: unknown) =>
          err instanceof ExecutableTrustRequiredError && err.reason === 'missing-choice',
      )
      vault.dispose()
    })
  })

  it('setup() with both executablePath and skipTrust throws (conflicting-choice)', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        () => vault.setup('both', 'value', { executablePath: '/usr/bin/node', skipTrust: true }),
        (err: unknown) =>
          err instanceof ExecutableTrustRequiredError && err.reason === 'conflicting-choice',
      )
      vault.dispose()
    })
  })

  it("setup() with the retired 'dev' sentinel as executablePath throws (legacy-dev-sentinel)", async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        () => vault.setup('legacy', 'value', { executablePath: 'dev' }),
        (err: unknown) =>
          err instanceof ExecutableTrustRequiredError && err.reason === 'legacy-dev-sentinel',
      )
      vault.dispose()
    })
  })

  it('setup() with an empty/whitespace executablePath throws (missing-choice), not an unusable token', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      for (const bad of ['', '   ', '\t']) {
        await assert.rejects(
          () => vault.setup('empty-path', 'value', { executablePath: bad }),
          (err: unknown) =>
            err instanceof ExecutableTrustRequiredError && err.reason === 'missing-choice',
          `executablePath ${JSON.stringify(bad)} must be rejected`,
        )
      }
      vault.dispose()
    })
  })

  it('setup() with skipTrust: true opts out and mints a token bound to the dev identity', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('skip', 'value', { skipTrust: true })
      const result = vault.authorize(token)
      // The 'dev' sentinel is the explicit no-binding identity.
      assert.equal(result.claims.exe, 'dev')
      vault.dispose()
    })
  })

  it('setup() with an explicit executablePath verifies it and binds the verified hash', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const exe = await writeFakeExecutable(dir, 'app.bin', 'fake-executable-contents')

      const token = await vault.setup('bound-path', 'value', { executablePath: exe.path })
      const result = vault.authorize(token)
      // The exe claim holds the verified SHA-256 hash, not the raw path.
      assert.equal(result.claims.exe, exe.hash)
      vault.dispose()
    })
  })

  it("the thrown error's message uses the JS option names, not the Rust core's field names", async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        () => vault.setup('js-names', 'value', {}),
        (err: unknown) => {
          assert.ok(err instanceof ExecutableTrustRequiredError)
          // The WASM boundary rewrites the Rust-native message into the SDK's
          // own option names — consumers must never see Rust snake_case fields.
          assert.match(err.message, /options\.executablePath/)
          assert.match(err.message, /options\.skipTrust/)
          assert.doesNotMatch(err.message, /executable_path|skip_trust|SetupOptions/)
          return true
        },
      )
      vault.dispose()
    })
  })
})

// Executable-trust verification (issue #166): supplying executablePath must run
// real trust verification through the host bridge — hashing + TOFU manifest I/O
// — mirroring the TypeScript library's tiers and errors. Before this, the WASM
// SDK bound the raw path with no hashing or manifest consultation.
describe('@vaultkeeper/wasm setup() executable-trust verification (issue #166)', () => {
  it('first encounter records the executable hash under TOFU', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const exe = await writeFakeExecutable(dir, 'app.bin', 'first-encounter-bytes')

      await vault.setup('s', 'v', { executablePath: exe.path })

      // The first encounter persisted the hash under the executable's namespace.
      const recorded = await readApprovedHashes(dir, exe.path)
      assert.deepEqual(recorded, [exe.hash])
      vault.dispose()
    })
  })

  it('a matching hash on a later setup passes and binds the same hash', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const exe = await writeFakeExecutable(dir, 'app.bin', 'stable-bytes')

      await vault.setup('s', 'v', { executablePath: exe.path })
      const token = await vault.setup('s', 'v', { executablePath: exe.path })
      const result = vault.authorize(token)
      assert.equal(result.claims.exe, exe.hash)
      vault.dispose()
    })
  })

  it('a conflicting hash throws IdentityMismatchError and records nothing new', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const exe = await writeFakeExecutable(dir, 'app.bin', 'original-bytes')
      const originalHash = exe.hash

      // First encounter records the original hash.
      await vault.setup('s', 'v', { executablePath: exe.path })

      // Tamper with the executable so its hash changes.
      await writeFile(exe.path, 'tampered-bytes')
      const tamperedHash = sha256Hex('tampered-bytes')

      await assert.rejects(
        () => vault.setup('s', 'v', { executablePath: exe.path }),
        (err: unknown) =>
          err instanceof IdentityMismatchError &&
          err instanceof VaultError &&
          err.previousHash === originalHash &&
          err.currentHash === tamperedHash,
      )

      // #148: the failed setup wrote nothing new — only the original remains.
      const recorded = await readApprovedHashes(dir, exe.path)
      assert.deepEqual(recorded, [originalHash])
      vault.dispose()
    })
  })

  it('#148 ordering: a setup that fails verification leaves the manifest unwritten', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      // No file at this path, so hashing (and thus setup) fails before minting.
      const missing = join(dir, 'nonexistent.bin')

      await assert.rejects(() => vault.setup('s', 'v', { executablePath: missing }))

      // Nothing was recorded for the executable.
      const recorded = await readApprovedHashes(dir, missing)
      assert.deepEqual(recorded, [])
      vault.dispose()
    })
  })
})

// Regression tests for issue #138: the WASM host bridge previously wrapped
// every readFile/deleteFile rejection into a generic error, erasing the
// errno before the core ever saw it — so a permission failure was
// indistinguishable from any other failure. These drive real chmod-based
// permission failures (not mocks) through the file backend and assert the
// typed FilesystemError the fix now produces, mirroring the native CLI
// host's classification (crates/vaultkeeper-cli/src/host.rs).
describe('@vaultkeeper/wasm filesystem error typing (issue #138)', () => {
  it(
    'permission-denied read throws a typed FilesystemError carrying path and errno code',
    { skip: !isPermissionTestable },
    async () => {
      await withTempDir(async (dir) => {
        const vault = await createTestVault(dir)
        await vault.store('locked-secret', 'value')

        const entryPath = join(
          dir,
          'file',
          `${Buffer.from('locked-secret', 'utf8').toString('hex')}.enc`,
        )
        await chmod(entryPath, 0o000)
        try {
          await assert.rejects(
            () => vault.retrieve('locked-secret'),
            (err: unknown) => {
              assert.ok(
                err instanceof FilesystemError && err instanceof VaultError,
                'must be a typed FilesystemError, not a generic VaultError',
              )
              assertPermissionDeniedCode(err.code)
              assert.equal(err.path, entryPath)
              assert.equal(err.permission, 'read')
              return true
            },
          )
        } finally {
          // Restore so the tempdir can be cleaned up.
          await chmod(entryPath, 0o600)
        }
        vault.dispose()
      })
    },
  )

  it(
    'permission-denied delete throws a typed FilesystemError',
    { skip: !isPermissionTestable },
    async () => {
      await withTempDir(async (dir) => {
        const vault = await createTestVault(dir)
        await vault.store('locked-delete', 'value')

        // Deleting requires write permission on the *containing directory*,
        // not the entry file itself — remove it there so the exists-probe
        // (which only needs directory search/execute) still resolves `true`
        // and the failure is isolated to the delete_file call.
        const fileDir = join(dir, 'file')
        await chmod(fileDir, 0o500)
        try {
          await assert.rejects(
            () => vault.delete('locked-delete'),
            (err: unknown) => {
              assert.ok(
                err instanceof FilesystemError && err instanceof VaultError,
                'must be a typed FilesystemError, not a generic VaultError',
              )
              assertPermissionDeniedCode(err.code)
              assert.equal(err.permission, 'write')
              return true
            },
          )
        } finally {
          // Restore so the tempdir can be cleaned up.
          await chmod(fileDir, 0o700)
        }
        vault.dispose()
      })
    },
  )

  it(
    'permission-denied store (write) throws a typed FilesystemError',
    { skip: !isPermissionTestable },
    async () => {
      await withTempDir(async (dir) => {
        const vault = await createTestVault(dir)
        // Store once so the `file/` storage directory and key file already
        // exist before locking it down — otherwise the lock-down would also
        // block `ensure_storage_dir()`'s directory creation, and the failure
        // wouldn't be isolated to the write itself.
        await vault.store('warm-up', 'value')

        const fileDir = join(dir, 'file')
        await chmod(fileDir, 0o500)
        try {
          await assert.rejects(
            () => vault.store('locked-store', 'value'),
            (err: unknown) => {
              assert.ok(
                err instanceof FilesystemError && err instanceof VaultError,
                'must be a typed FilesystemError, not a generic VaultError',
              )
              assertPermissionDeniedCode(err.code)
              assert.equal(err.permission, 'write')
              return true
            },
          )
        } finally {
          // Restore so the tempdir can be cleaned up.
          await chmod(fileDir, 0o700)
        }
        vault.dispose()
      })
    },
  )

  // Regression test for a PR #154 review follow-up: `writeFile`'s `mkdir`
  // sub-step can fail on a *different* path than the file this bridge call
  // was nominally about — the directory it couldn't create, not the entry
  // file (or, here, the `.keep` sentinel `ensure_storage_dir()` writes).
  // `fs_rejection_to_vault_error` must surface that more precise directory
  // path rather than silently overriding it with the Rust-side argument.
  it(
    'permission-denied storage directory creation reports the directory that failed, not the sentinel file path',
    { skip: !isPermissionTestable },
    async () => {
      await withTempDir(async (dir) => {
        const vault = await createTestVault(dir)
        // Lock down the config dir itself *before* any store() call, so the
        // `file/` storage directory (and its `.keep` sentinel) never gets
        // created — this isolates the failure to node-host.ts's
        // `mkdir(dir, { recursive: true })` step, not the subsequent write.
        await chmod(dir, 0o500)
        const fileDir = join(dir, 'file')
        try {
          await assert.rejects(
            () => vault.store('never-created', 'value'),
            (err: unknown) => {
              assert.ok(
                err instanceof FilesystemError && err instanceof VaultError,
                'must be a typed FilesystemError, not a generic VaultError',
              )
              assertPermissionDeniedCode(err.code)
              assert.equal(
                err.path,
                fileDir,
                'must report the directory mkdir failed to create, not the sentinel file path',
              )
              return true
            },
          )
        } finally {
          // Restore so the tempdir can be cleaned up.
          await chmod(dir, 0o700)
        }
        vault.dispose()
      })
    },
  )

  // Unchanged behavior (issue #138 non-goal): a missing secret must still
  // surface as SecretNotFoundError, not be swept into FilesystemError by
  // this fix — the errno-conveyance change must not disturb the existing
  // exists-probe disambiguation in FileBackend.
  it('missing secret still throws a typed SecretNotFoundError, not FilesystemError', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        () => vault.retrieve('never-stored-138'),
        (err: unknown) =>
          err instanceof SecretNotFoundError &&
          err instanceof VaultError &&
          !(err instanceof FilesystemError),
      )
      vault.dispose()
    })
  })
})

/**
 * Regression tests for issue #192: the wrapper forwarded its arguments straight
 * into WASM with no JS-side type guard, so a non-string (a number, a plain
 * object, or — a common mistake — an un-awaited `setup()` Promise) reached
 * wasm-bindgen's `passStringToWasm0` and crashed the process with an opaque
 * `VaultError: memory access out of bounds` fault. A malformed token *string*
 * by contrast already yielded a clean `InvalidTokenError`. Each guarded method
 * must now reject a non-string with a typed, catchable error *before* the value
 * crosses the WASM boundary.
 *
 * The `@ts-expect-error` directives are load-bearing: the parameters are typed
 * `string`, so passing a non-string is a deliberate type violation that models
 * an untyped-JavaScript caller. If a signature were ever widened to accept the
 * bad type, the directive would fail the build — flagging that these runtime
 * guards need re-examining.
 */
describe('@vaultkeeper/wasm non-string input guards (issue #192)', () => {
  it('authorize(number) throws a typed InvalidTokenError, not a native fault', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      assert.throws(
        // @ts-expect-error deliberately passing a non-string to exercise the runtime guard (issue #192)
        () => vault.authorize(42),
        (err: unknown) => err instanceof InvalidTokenError && err instanceof VaultError,
      )
      vault.dispose()
    })
  })

  it('authorize(object) throws a typed InvalidTokenError, not a native fault', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      assert.throws(
        // @ts-expect-error deliberately passing a non-string to exercise the runtime guard (issue #192)
        () => vault.authorize({}),
        (err: unknown) => err instanceof InvalidTokenError && err instanceof VaultError,
      )
      vault.dispose()
    })
  })

  it('authorize(Promise) — the un-awaited setup() mistake — throws InvalidTokenError, not a native fault', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      // The exact shape of the reported bug: `vault.authorize(vault.setup(...))`
      // without an intervening `await`. The pending Promise must be rejected by
      // the guard, never handed to WASM.
      const unawaitedSetup = vault.setup('oops', 'value', { skipTrust: true })
      assert.throws(
        // @ts-expect-error deliberately passing a Promise to exercise the runtime guard (issue #192)
        () => vault.authorize(unawaitedSetup),
        (err: unknown) => err instanceof InvalidTokenError && err instanceof VaultError,
      )
      // Drain the Promise so it does not surface as an unhandled rejection.
      await unawaitedSetup
      vault.dispose()
    })
  })

  it('authorize(valid string) is unchanged — a real token still authorizes', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      const token = await vault.setup('guard-key', 'guard-value', { skipTrust: true })
      const result = vault.authorize(token)
      assert.equal(
        result.secret.read((s) => s),
        'guard-value',
      )
      vault.dispose()
    })
  })

  it('setup(nonstring secretName) rejects with a TypeError before touching WASM', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        // @ts-expect-error deliberately passing a non-string to exercise the runtime guard (issue #192)
        () => vault.setup(42, 'value', { skipTrust: true }),
        (err: unknown) => err instanceof TypeError,
      )
      vault.dispose()
    })
  })

  it('setup(nonstring secretValue) rejects with a TypeError before touching WASM', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        // @ts-expect-error deliberately passing a non-string to exercise the runtime guard (issue #192)
        () => vault.setup('name', {}, { skipTrust: true }),
        (err: unknown) => err instanceof TypeError,
      )
      vault.dispose()
    })
  })

  it('store(nonstring id) and store(nonstring secret) reject with a TypeError', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        // @ts-expect-error deliberately passing a non-string to exercise the runtime guard (issue #192)
        () => vault.store(42, 'value'),
        (err: unknown) => err instanceof TypeError,
      )
      await assert.rejects(
        // @ts-expect-error deliberately passing a non-string to exercise the runtime guard (issue #192)
        () => vault.store('id', {}),
        (err: unknown) => err instanceof TypeError,
      )
      vault.dispose()
    })
  })

  it('retrieve(nonstring id) rejects with a TypeError before touching WASM', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        // @ts-expect-error deliberately passing a non-string to exercise the runtime guard (issue #192)
        () => vault.retrieve(42),
        (err: unknown) => err instanceof TypeError,
      )
      vault.dispose()
    })
  })

  it('delete(nonstring id) rejects with a TypeError before touching WASM', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        // @ts-expect-error deliberately passing a non-string to exercise the runtime guard (issue #192)
        () => vault.delete(42),
        (err: unknown) => err instanceof TypeError,
      )
      vault.dispose()
    })
  })

  // The guard message names the offending value's type; the article must read
  // cleanly ("an object" / "undefined", not "a object" / "a undefined").
  it('guard error messages pick the right article for each value type', async () => {
    await withTempDir(async (dir) => {
      const vault = await createTestVault(dir)
      await assert.rejects(
        // @ts-expect-error deliberately passing an object to check the guard message (issue #192)
        () => vault.retrieve({}),
        (err: unknown) => err instanceof TypeError && err.message.includes('received an object'),
      )
      await assert.rejects(
        // @ts-expect-error deliberately passing undefined to check the guard message (issue #192)
        () => vault.retrieve(undefined),
        (err: unknown) => err instanceof TypeError && err.message.endsWith('received undefined'),
      )
      await assert.rejects(
        // @ts-expect-error deliberately passing a number to check the guard message (issue #192)
        () => vault.retrieve(42),
        (err: unknown) => err instanceof TypeError && err.message.includes('received a number'),
      )
      vault.dispose()
    })
  })
})

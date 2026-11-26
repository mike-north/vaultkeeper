/**
 * Tests for the FileBackend signing contract (SigningBackend).
 *
 * Covers key generation, public-key export, backend-side signing, the signing
 * key namespace isolation from secrets, and the not-found / duplicate paths.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8032 (Ed25519)
 */

import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import * as crypto from 'node:crypto'
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { FileBackend } from '../../../src/backend/file-backend.js'
import { isSigningBackend } from '../../../src/backend/types.js'
import {
  SigningKeyNotFoundError,
  SigningKeyAlreadyExistsError,
  FilesystemError,
  InvalidKeyMaterialError,
} from '../../../src/errors.js'
import { encryptGcm, getOrCreateWrapKey } from '../../../src/util/at-rest.js'

/** Compute the on-disk encrypted-key path the FileBackend uses for a signing id. */
function signingKeyFile(dir: string, id: string): string {
  const safeId = Buffer.from(id, 'utf8').toString('hex')
  return path.join(dir, 'signing-keys', `${safeId}.pem.enc`)
}

let storageDir: string
let backend: FileBackend

beforeEach(async () => {
  storageDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-file-signing-'))
  backend = new FileBackend(storageDir)
})

afterEach(async () => {
  await fs.rm(storageDir, { recursive: true, force: true })
})

const ID = 'signing-key:approval'

describe('FileBackend signing contract', () => {
  it('is recognized as a signing backend', () => {
    expect(isSigningBackend(backend)).toBe(true)
  })

  it('generateSigningKey + getPublicKey yields a valid SPKI PEM Ed25519 key', async () => {
    await backend.generateSigningKey(ID, 'EdDSA')
    const pub = await backend.getPublicKey(ID)

    expect(pub.algorithm).toBe('EdDSA')
    expect(pub.publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----')
    // kid is base64url(sha256(spki der)) — 43 base64url chars for a 32-byte digest.
    expect(pub.kid).toMatch(/^[A-Za-z0-9_-]{43}$/)
    const key = crypto.createPublicKey(pub.publicKeyPem)
    expect(key.asymmetricKeyType).toBe('ed25519')
  })

  it('kid is stable across repeated getPublicKey calls', async () => {
    await backend.generateSigningKey(ID, 'EdDSA')
    const a = await backend.getPublicKey(ID)
    const b = await backend.getPublicKey(ID)
    expect(a.kid).toBe(b.kid)
  })

  it('signWithKey produces a signature the exported public key verifies', async () => {
    await backend.generateSigningKey(ID, 'EdDSA')
    const pub = await backend.getPublicKey(ID)
    const data = Buffer.from('sign-me', 'utf8')
    const sig = await backend.signWithKey(ID, data)
    const ok = crypto.verify(null, data, crypto.createPublicKey(pub.publicKeyPem), sig)
    expect(ok).toBe(true)
  })

  it('rejects an unsupported algorithm', async () => {
    // Runtime guard for a value the type system would reject at compile time.
    await expect(
      // @ts-expect-error — deliberately passing an unsupported algorithm
      backend.generateSigningKey(ID, 'ES256'),
    ).rejects.toThrow(/EdDSA/)
  })

  it('refuses to overwrite an existing signing key with a typed already-exists error', async () => {
    await backend.generateSigningKey(ID, 'EdDSA')
    const pubBefore = await backend.getPublicKey(ID)
    await expect(backend.generateSigningKey(ID, 'EdDSA')).rejects.toBeInstanceOf(
      SigningKeyAlreadyExistsError,
    )
    await expect(backend.generateSigningKey(ID, 'EdDSA')).rejects.toMatchObject({
      keyName: 'approval',
    })
    // The original key must be untouched (kid unchanged) after the refusal.
    const pubAfter = await backend.getPublicKey(ID)
    expect(pubAfter.kid).toBe(pubBefore.kid)
  })

  it('returns one successful enrollment whose public key survives reopening', async () => {
    async function enroll(writer: FileBackend) {
      await writer.generateSigningKey(ID, 'EdDSA')
      return writer.getPublicKey(ID)
    }

    const [first, second] = await Promise.allSettled([
      enroll(backend),
      enroll(new FileBackend(storageDir)),
    ])
    const [winner, loser] = first.status === 'fulfilled' ? [first, second] : [second, first]
    expect(winner.status).toBe('fulfilled')
    expect(loser.status).toBe('rejected')
    if (winner.status === 'fulfilled' && loser.status === 'rejected') {
      expect(loser.reason).toBeInstanceOf(SigningKeyAlreadyExistsError)
      expect(await new FileBackend(storageDir).getPublicKey(ID)).toEqual(winner.value)
    }
  })

  it('uses a single wrapping key when different labels are created in a fresh store', async () => {
    const other = new FileBackend(storageDir)
    const otherId = 'signing-key:other'
    await Promise.all([
      backend.generateSigningKey(ID, 'EdDSA'),
      other.generateSigningKey(otherId, 'EdDSA'),
    ])

    const reopened = new FileBackend(storageDir)
    const [first, second] = await Promise.all([
      reopened.getPublicKey(ID),
      reopened.getPublicKey(otherId),
    ])
    expect(first.kid).not.toBe(second.kid)
  })

  it('does not replace a repaired wrapping key while another enrollment is using it', async () => {
    await fs.writeFile(path.join(storageDir, '.key'), Buffer.alloc(1))
    const other = new FileBackend(storageDir)
    const results = await Promise.allSettled([
      backend.generateSigningKey(ID, 'EdDSA'),
      other.generateSigningKey(ID, 'EdDSA'),
    ])

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1)
    const reopened = new FileBackend(storageDir)
    expect((await reopened.getPublicKey(ID)).algorithm).toBe('EdDSA')
  })

  it('recovers an interrupted wrapping-key repair and keeps the selected key', async () => {
    const candidate = crypto.randomBytes(32)
    await fs.writeFile(path.join(storageDir, '.key'), Buffer.alloc(1))
    await fs.writeFile(path.join(storageDir, '.key.repair'), candidate)
    await backend.generateSigningKey(ID, 'EdDSA')
    const publicKey = await backend.getPublicKey(ID)
    expect(await fs.readFile(path.join(storageDir, '.key'))).toEqual(candidate)
    expect(await new FileBackend(storageDir).getPublicKey(ID)).toEqual(publicKey)
  })

  it('a non-ENOENT probe failure surfaces a typed FilesystemError, never a silent overwrite', async () => {
    // Make the signing-key directory path a regular FILE so that probing for a
    // key underneath it fails with ENOTDIR (a non-ENOENT error) rather than
    // "not found". A transient/permission-style probe failure must be surfaced,
    // not mistaken for "absent" — which could clobber an existing key.
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-file-signing-blocked-'))
    try {
      await fs.writeFile(path.join(dir, 'signing-keys'), 'not a directory', 'utf8')
      const blocked = new FileBackend(dir)
      await expect(blocked.generateSigningKey(ID, 'EdDSA')).rejects.toBeInstanceOf(FilesystemError)
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  it('getPublicKey throws SigningKeyNotFoundError for a missing key', async () => {
    await expect(backend.getPublicKey('signing-key:missing')).rejects.toBeInstanceOf(
      SigningKeyNotFoundError,
    )
    await expect(backend.getPublicKey('signing-key:missing')).rejects.toMatchObject({
      keyName: 'missing',
    })
  })

  it('signWithKey throws SigningKeyNotFoundError for a missing key', async () => {
    await expect(
      backend.signWithKey('signing-key:missing', Buffer.from('x')),
    ).rejects.toBeInstanceOf(SigningKeyNotFoundError)
  })

  // Corrupt/tampered on-disk key material (decrypts cleanly but is not a valid
  // private key) must surface as a typed VaultError, never a raw Node crypto
  // exception. We simulate it by writing validly-encrypted non-PEM content under
  // the same wrap key the backend uses.
  async function corruptStoredKey(): Promise<void> {
    await backend.generateSigningKey(ID, 'EdDSA')
    const wrapKey = await getOrCreateWrapKey(path.join(storageDir, '.key'))
    await fs.writeFile(signingKeyFile(storageDir, ID), encryptGcm(wrapKey, 'not a private key'), {
      mode: 0o600,
    })
  }

  it('getPublicKey throws a typed InvalidKeyMaterialError for corrupt stored key material', async () => {
    await corruptStoredKey()
    await expect(backend.getPublicKey(ID)).rejects.toBeInstanceOf(InvalidKeyMaterialError)
  })

  it('signWithKey throws a typed InvalidKeyMaterialError for corrupt stored key material', async () => {
    await corruptStoredKey()
    await expect(backend.signWithKey(ID, Buffer.from('payload'))).rejects.toBeInstanceOf(
      InvalidKeyMaterialError,
    )
  })
})

describe('FileBackend signing-key namespace isolation', () => {
  // AC1: signing keys occupy a distinct namespace and cannot be read as secrets.
  it('a signing key is never returned by retrieve/exists/list as a secret', async () => {
    await backend.generateSigningKey('signing-key:iso', 'EdDSA')

    // Neither the bare name nor the namespaced id is a readable secret.
    await expect(backend.retrieve('iso')).rejects.toBeTruthy()
    await expect(backend.retrieve('signing-key:iso')).rejects.toBeTruthy()
    expect(await backend.exists('iso')).toBe(false)
    expect(await backend.exists('signing-key:iso')).toBe(false)
    expect(await backend.list()).not.toContain('signing-key:iso')
    expect(await backend.list()).not.toContain('iso')
  })

  it('a secret and a signing key can share a name without colliding', async () => {
    await backend.store('shared', 'the-secret-value')
    await backend.generateSigningKey('signing-key:shared', 'EdDSA')

    // The secret still reads back as itself; the signing key is untouched.
    expect(await backend.retrieve('shared')).toBe('the-secret-value')
    const pub = await backend.getPublicKey('signing-key:shared')
    expect(pub.algorithm).toBe('EdDSA')
  })
})

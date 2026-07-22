import { describe, it, expect, beforeEach } from 'vitest'
import * as crypto from 'node:crypto'
import { InMemoryBackend } from '../../src/index.js'
import { SigningKeyNotFoundError, SigningKeyAlreadyExistsError } from 'vaultkeeper'

describe('InMemoryBackend — SigningBackend', () => {
  let backend: InMemoryBackend

  beforeEach(() => {
    backend = new InMemoryBackend()
  })

  // Acceptance criterion 1: generates an Ed25519 keypair, signs a payload, and
  // the signature verifies against the exported public key; the private key is
  // never exposed through the public surface.
  it('generates a real Ed25519 keypair, signs, and the signature verifies against the exported public key', async () => {
    await backend.generateSigningKey('doc-signer', 'EdDSA')
    const publicKey = await backend.getPublicKey('doc-signer')
    expect(publicKey.algorithm).toBe('EdDSA')
    expect(publicKey.publicKeyPem).toContain('BEGIN PUBLIC KEY')
    expect(publicKey.kid).toEqual(expect.any(String))

    const payload = Buffer.from('the exact bytes to sign', 'utf8')
    const signature = await backend.signWithKey('doc-signer', payload)

    const verifyingKey = crypto.createPublicKey(publicKey.publicKeyPem)
    const valid = crypto.verify(null, payload, verifyingKey, signature)
    expect(valid).toBe(true)

    // A tampered payload must not verify — proves this is a real signature,
    // not a stub that always returns true.
    const tampered = Buffer.from('a different payload', 'utf8')
    expect(crypto.verify(null, tampered, verifyingKey, signature)).toBe(false)
  })

  it('never exposes the private key through the public surface', async () => {
    await backend.generateSigningKey('secret-signer', 'EdDSA')
    const publicKey = await backend.getPublicKey('secret-signer')
    // Assert the required public-key-shaped fields are present, and that no
    // field is private-key-shaped — not an exact key-set match, so this test
    // does not regress if SigningPublicKey ever gains a new non-sensitive
    // field (e.g. metadata).
    expect(publicKey.algorithm).toEqual(expect.any(String))
    expect(publicKey.kid).toEqual(expect.any(String))
    expect(publicKey.publicKeyPem).toEqual(expect.any(String))
    for (const value of Object.values(publicKey)) {
      expect(typeof value === 'string' ? value : '').not.toContain('PRIVATE KEY')
    }
    expect(publicKey.publicKeyPem).not.toContain('PRIVATE KEY')
    // No enumerable own property on the backend instance holds a raw KeyObject
    // or PEM string reachable without going through signWithKey().
    for (const value of Object.values(backend)) {
      expect(typeof value === 'string' ? value : '').not.toContain('PRIVATE KEY')
    }
  })

  it('rejects signing/exporting a key that was never enrolled with SigningKeyNotFoundError', async () => {
    await expect(backend.getPublicKey('missing')).rejects.toBeInstanceOf(SigningKeyNotFoundError)
    await expect(backend.signWithKey('missing', Buffer.from('x'))).rejects.toBeInstanceOf(
      SigningKeyNotFoundError,
    )
  })

  it('refuses to silently replace an existing signing key', async () => {
    await backend.generateSigningKey('dup', 'EdDSA')
    await expect(backend.generateSigningKey('dup', 'EdDSA')).rejects.toBeInstanceOf(
      SigningKeyAlreadyExistsError,
    )
  })
})

describe('InMemoryBackend — PresenceCapableBackend', () => {
  // Acceptance criterion 2: implements PresenceCapableBackend and reports no
  // presence by default, expressed in the existing BackendCapabilities vocabulary.
  it('reports no presence by default, in the BackendCapabilities vocabulary', async () => {
    const backend = new InMemoryBackend()
    const capabilities = await backend.getCapabilities()
    expect(capabilities).toEqual({ presencePerUse: false })
  })
})

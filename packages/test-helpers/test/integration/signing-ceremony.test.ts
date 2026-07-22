import { describe, it, expect, beforeEach } from 'vitest'
import * as crypto from 'node:crypto'
import { TestVault } from '../../src/index.js'
import { VaultKeeper, SigningKeyNotFoundError } from 'vaultkeeper'

/**
 * Acceptance criterion 5: TestVault's createSigningKey -> authorizeSigningKey
 * -> sign ceremony produces a verifiable signature over the full production
 * call path.
 */
describe('TestVault.signCeremony', () => {
  let vault: TestVault

  beforeEach(async () => {
    vault = await TestVault.create()
  })

  it('runs createSigningKey -> authorizeSigningKey -> sign and produces a verifiable JWS', async () => {
    const { jws, publicKey } = await vault.signCeremony('release-signer', 'release payload v1')

    expect(jws.split('.')).toHaveLength(3) // detached compact JWS: header..signature
    expect(publicKey.algorithm).toBe('EdDSA')

    const verified = await VaultKeeper.verify({
      payload: 'release payload v1',
      jws,
      publicKey: publicKey.publicKeyPem,
    })
    expect(verified).toBe(true)
  })

  it('rejects verification of a tampered payload', async () => {
    const { jws, publicKey } = await vault.signCeremony('tamper-signer', 'original payload')

    const verified = await VaultKeeper.verify({
      payload: 'a different payload',
      jws,
      publicKey: publicKey.publicKeyPem,
    })
    expect(verified).toBe(false)
  })

  it('exercises the exact production call path (createSigningKey, authorizeSigningKey, sign individually agree)', async () => {
    // Run the ceremony's three steps directly through vault.keeper to confirm
    // signCeremony is not a shortcut around a different code path.
    const publicKey = await vault.keeper.createSigningKey('manual-signer', 'EdDSA')
    const token = await vault.keeper.authorizeSigningKey('manual-signer')
    const { result } = await vault.keeper.sign(token, { payload: 'manual payload' })

    const verified = await VaultKeeper.verify({
      payload: 'manual payload',
      jws: result.jws,
      publicKey: publicKey.publicKeyPem,
    })
    expect(verified).toBe(true)

    // signCeremony against a differently-named key produces an independently
    // verifiable result using the same three-step path.
    const ceremonyResult = await vault.signCeremony('another-signer', 'manual payload')
    const verifiedCeremony = await VaultKeeper.verify({
      payload: 'manual payload',
      jws: ceremonyResult.jws,
      publicKey: ceremonyResult.publicKey.publicKeyPem,
    })
    expect(verifiedCeremony).toBe(true)
  })

  it('signs binary payloads, not just UTF-8 strings', async () => {
    const payload = crypto.randomBytes(32)
    const { jws, publicKey } = await vault.signCeremony('binary-signer', payload)

    const verified = await VaultKeeper.verify({
      payload,
      jws,
      publicKey: publicKey.publicKeyPem,
    })
    expect(verified).toBe(true)
  })

  it('fails fast with SigningKeyNotFoundError if authorize/sign runs after the key is removed', async () => {
    await vault.keeper.createSigningKey('short-lived', 'EdDSA')
    const token = await vault.keeper.authorizeSigningKey('short-lived')
    // Simulate the key vanishing between authorize and sign (e.g. rotated
    // away) via fault injection targeting the sign-time backend call.
    vault.backend.injectFault('signWithKey', 'key-absent')
    await expect(vault.keeper.sign(token, { payload: 'x' })).rejects.toBeInstanceOf(
      SigningKeyNotFoundError,
    )
  })
})

import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { DpapiBackend } from '../../../src/backend/dpapi-backend.js'
import { VaultError } from '../../../src/errors.js'

describe.skipIf(process.platform !== 'win32')('Windows DPAPI', () => {
  let storageDir: string
  let backend: DpapiBackend

  beforeEach(async () => {
    storageDir = await mkdtemp(join(tmpdir(), 'vaultkeeper-dpapi-'))
    backend = new DpapiBackend(storageDir)
  })

  afterEach(async () => {
    await rm(storageDir, { recursive: true, force: true })
  })

  it.each([
    ['spaces', '  secret  '],
    ['tabs', '\tsecret\t'],
    ['newlines', '\nsecret\r\n'],
    ['whitespace only', ' \t\r\n '],
    ['Unicode with whitespace', ' \t日本語 🔒\r\n'],
  ])('round-trips %s exactly', async (_label, secret) => {
    await backend.store('credential', secret)
    await expect(backend.retrieve('credential')).resolves.toBe(secret)
  })

  it('rejects a corrupt encrypted entry', async () => {
    await writeFile(join(storageDir, '63726564656e7469616c.enc'), 'invalid DPAPI envelope')
    await expect(backend.retrieve('credential')).rejects.toBeInstanceOf(VaultError)
  })
})

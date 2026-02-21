/**
 * Integration test for FileBackend with real filesystem.
 *
 * @remarks
 * These tests use a real temp directory and spawn real openssl commands.
 * They are skipped when openssl is not installed.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import * as fs from 'node:fs/promises'
import * as osModule from 'node:os'
import * as path from 'node:path'

// We need to redirect homedir before FileBackend is imported so that the
// storage path is computed using our temp dir. Use a module-level variable
// that the mock can close over.
let overriddenHome = ''

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof osModule>()
  return {
    ...actual,
    homedir: () => (overriddenHome !== '' ? overriddenHome : actual.homedir()),
  }
})

import { execCommandFull } from '../../../src/util/exec.js'
import { FileBackend } from '../../../src/backend/file-backend.js'
import { SecretNotFoundError } from '../../../src/errors.js'

let opensslAvailable = false
let tmpDir = ''

beforeAll(async () => {
  // Check if openssl is installed
  try {
    const result = await execCommandFull('openssl', ['version'])
    opensslAvailable = result.exitCode === 0
  } catch {
    opensslAvailable = false
  }

  if (!opensslAvailable) {
    return
  }

  tmpDir = await fs.mkdtemp(path.join(osModule.tmpdir(), 'vaultkeeper-integration-'))
  overriddenHome = tmpDir
})

afterAll(async () => {
  overriddenHome = ''

  if (tmpDir) {
    await fs.rm(tmpDir, { recursive: true, force: true })
  }
})

describe('FileBackend integration', () => {
  it('should store and retrieve a secret', async () => {
    if (!opensslAvailable) {
      console.log('Skipping: openssl not available')
      return
    }

    const backend = new FileBackend()
    await backend.store('integration-test-id', 'integration-test-secret')
    const retrieved = await backend.retrieve('integration-test-id')
    expect(retrieved).toBe('integration-test-secret')
  })

  it('should store and verify existence', async () => {
    if (!opensslAvailable) {
      console.log('Skipping: openssl not available')
      return
    }

    const backend = new FileBackend()
    await backend.store('existence-test', 'some-value')
    const exists = await backend.exists('existence-test')
    expect(exists).toBe(true)
  })

  it('should return false for non-existent secret', async () => {
    if (!opensslAvailable) {
      console.log('Skipping: openssl not available')
      return
    }

    const backend = new FileBackend()
    const exists = await backend.exists('nonexistent-id-xyz')
    expect(exists).toBe(false)
  })

  it('should throw SecretNotFoundError when retrieving non-existent secret', async () => {
    if (!opensslAvailable) {
      console.log('Skipping: openssl not available')
      return
    }

    const backend = new FileBackend()
    await expect(backend.retrieve('nonexistent-retrieve-xyz')).rejects.toBeInstanceOf(
      SecretNotFoundError,
    )
  })

  it('should delete a stored secret', async () => {
    if (!opensslAvailable) {
      console.log('Skipping: openssl not available')
      return
    }

    const backend = new FileBackend()
    await backend.store('delete-test', 'delete-me')
    await backend.delete('delete-test')
    const exists = await backend.exists('delete-test')
    expect(exists).toBe(false)
  })

  it('should throw SecretNotFoundError when deleting non-existent secret', async () => {
    if (!opensslAvailable) {
      console.log('Skipping: openssl not available')
      return
    }

    const backend = new FileBackend()
    await expect(backend.delete('nonexistent-delete-xyz')).rejects.toBeInstanceOf(
      SecretNotFoundError,
    )
  })

  it('should handle secrets with special characters', async () => {
    if (!opensslAvailable) {
      console.log('Skipping: openssl not available')
      return
    }

    const backend = new FileBackend()
    const specialSecret = 'sp3c!al ch@rs & m0re'
    await backend.store('special-chars-id', specialSecret)
    const retrieved = await backend.retrieve('special-chars-id')
    expect(retrieved).toBe(specialSecret)
  })

  it('should store multiple independent secrets', async () => {
    if (!opensslAvailable) {
      console.log('Skipping: openssl not available')
      return
    }

    const backend = new FileBackend()
    await backend.store('multi-a', 'secret-a')
    await backend.store('multi-b', 'secret-b')
    await backend.store('multi-c', 'secret-c')

    expect(await backend.retrieve('multi-a')).toBe('secret-a')
    expect(await backend.retrieve('multi-b')).toBe('secret-b')
    expect(await backend.retrieve('multi-c')).toBe('secret-c')
  })
})

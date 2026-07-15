/**
 * Tests for 1Password SDK integration constants.
 *
 * @see https://developer.1password.com/docs/sdks/
 */

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  INTEGRATION_NAME,
  getIntegrationVersion,
  isModuleNotFoundError,
} from '../../../src/backend/one-password-constants.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

describe('one-password-constants', () => {
  it('INTEGRATION_NAME should be vaultkeeper', () => {
    expect(INTEGRATION_NAME).toBe('vaultkeeper')
  })

  it('getIntegrationVersion() should match package.json version', () => {
    const pkgPath = path.resolve(__dirname, '..', '..', '..', 'package.json')
    const raw: unknown = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
    expect(raw).toHaveProperty('version')
    const pkg = raw ?? {}
    expect(getIntegrationVersion()).toBe(
      pkg instanceof Object && 'version' in pkg ? pkg.version : undefined,
    )
  })

  describe('isModuleNotFoundError', () => {
    // Only a genuine module-resolution failure means "the optional peer is not
    // installed"; anything else is a present-but-broken SDK and must NOT be
    // reported as not-installed. Regression for
    // https://github.com/mike-north/vaultkeeper/issues/113.
    it('returns true for ESM module-not-found (ERR_MODULE_NOT_FOUND)', () => {
      const err = Object.assign(new Error('Cannot find package'), {
        code: 'ERR_MODULE_NOT_FOUND',
      })
      expect(isModuleNotFoundError(err)).toBe(true)
    })

    it('returns true for CJS module-not-found (MODULE_NOT_FOUND)', () => {
      const err = Object.assign(new Error('Cannot find module'), { code: 'MODULE_NOT_FOUND' })
      expect(isModuleNotFoundError(err)).toBe(true)
    })

    it('returns true when a module-not-found is wrapped via error.cause', () => {
      const cause = Object.assign(new Error('Cannot find package'), {
        code: 'ERR_MODULE_NOT_FOUND',
      })
      const wrapper = new Error('loader failed', { cause })
      expect(isModuleNotFoundError(wrapper)).toBe(true)
    })

    it('returns false for a present-but-broken SDK error (different code)', () => {
      const err = Object.assign(new Error('native binding failed to load'), {
        code: 'ERR_DLOPEN_FAILED',
      })
      expect(isModuleNotFoundError(err)).toBe(false)
    })

    it('returns false for an error with no code (e.g. an init throw)', () => {
      expect(isModuleNotFoundError(new Error('SDK init threw'))).toBe(false)
    })

    it('returns false for non-error values', () => {
      expect(isModuleNotFoundError(null)).toBe(false)
      expect(isModuleNotFoundError(undefined)).toBe(false)
      expect(isModuleNotFoundError('ERR_MODULE_NOT_FOUND')).toBe(false)
      expect(isModuleNotFoundError({})).toBe(false)
    })
  })
})

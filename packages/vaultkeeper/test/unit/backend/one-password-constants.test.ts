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
  INTEGRATION_VERSION,
} from '../../../src/backend/one-password-constants.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

describe('one-password-constants', () => {
  it('INTEGRATION_NAME should be vaultkeeper', () => {
    expect(INTEGRATION_NAME).toBe('vaultkeeper')
  })

  it('INTEGRATION_VERSION should match package.json version', () => {
    const pkgPath = path.resolve(__dirname, '..', '..', '..', 'package.json')
    const raw: unknown = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
    expect(raw).toHaveProperty('version')
    const pkg = raw ?? {}
    expect(INTEGRATION_VERSION).toBe(
      (pkg instanceof Object && 'version' in pkg) ? pkg.version : undefined,
    )
  })
})

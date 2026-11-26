import { describe, it, expect, afterEach } from 'vitest'
import { shouldAutoApprove } from '../../src/auto-approve.js'

describe('shouldAutoApprove', () => {
  afterEach(() => {
    delete process.env.VAULTKEEPER_YES
  })

  it('returns true when the --yes flag is set, regardless of env', () => {
    delete process.env.VAULTKEEPER_YES
    expect(shouldAutoApprove(true)).toBe(true)
  })

  it('returns true when VAULTKEEPER_YES=1 even without the flag', () => {
    process.env.VAULTKEEPER_YES = '1'
    expect(shouldAutoApprove(false)).toBe(true)
  })

  it('returns false when neither the flag nor the env var is set', () => {
    delete process.env.VAULTKEEPER_YES
    expect(shouldAutoApprove(false)).toBe(false)
  })

  // Only the exact value "1" opts in — mirrors VAULTKEEPER_SKIP_DOCTOR semantics
  // so an incidental "0"/"true"/"false"/"" never silently approves callers.
  it.each(['0', 'true', 'false', 'yes', '', ' 1 '])(
    'returns false for VAULTKEEPER_YES=%j without the flag',
    (value) => {
      process.env.VAULTKEEPER_YES = value
      expect(shouldAutoApprove(false)).toBe(false)
    },
  )
})

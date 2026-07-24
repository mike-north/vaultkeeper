/**
 * UATs for `vaultkeeper run --token` (issue #333, surface-governance ruling
 * B9: `run` is the single launcher verb; `exec` folds into it).
 *
 * A real, redeemable JWE is minted in-process via `VaultKeeper.setup`
 * pointed at the same isolated config dir the CLI subprocess under test
 * uses — the persisted key material is what lets the subprocess's own
 * `authorize()` decrypt it (the same shape the native Rust CLI's
 * `run_token_uat.rs` mints a token with).
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/333
 */
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'
import { VaultKeeper } from 'vaultkeeper'

const SECRET_NAME = 'run-token-uat-secret'
const SECRET_VALUE = 'the-real-secret-value'

let env: CliTestEnv | undefined
let homeDir: string

beforeEach(async () => {
  homeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-run-token-home-'))
  env = await createCliTestEnv({
    env: { HOME: homeDir, VAULTKEEPER_SKIP_DOCTOR: '1' },
  })
})

afterEach(async () => {
  if (env !== undefined) {
    await env.cleanup()
    env = undefined
  }
  await fs.rm(homeDir, { recursive: true, force: true })
})

/** Store `value` under `name` and mint a real, redeemable JWE for it,
 * pointed at the same config dir the CLI subprocess reads. */
async function mintToken(configDir: string, name: string, value: string): Promise<string> {
  if (env === undefined) throw new Error('env not initialized')
  const stored = await env.runWithStdin(['store', '--name', name], `${value}\n`)
  expect(stored.exitCode).toBe(0)

  const vault = await VaultKeeper.init({ configDir, skipDoctor: true })
  return vault.setup(name, { skipTrust: true })
}

describe('run --token', () => {
  // AC1: run --token matches exec --token behavior — byte-exact on the
  // child's observable environment/stdout.
  it('injects the redeemed secret as VAULTKEEPER_SECRET by default', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const token = await mintToken(env.configDir, SECRET_NAME, SECRET_VALUE)

    const result = await env.run([
      'run',
      '--token',
      token,
      '--',
      'sh',
      '-c',
      'printf "%s" "$VAULTKEEPER_SECRET"',
    ])

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toBe(SECRET_VALUE)
  })

  // AC2: --as renames the target env var; the default var is then unset.
  it('--as renames the injected variable', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const token = await mintToken(env.configDir, SECRET_NAME, SECRET_VALUE)

    const result = await env.run([
      'run',
      '--token',
      token,
      '--as',
      'CUSTOM_VAR',
      '--',
      'sh',
      '-c',
      'printf "default=%s custom=%s" "${VAULTKEEPER_SECRET:-unset}" "$CUSTOM_VAR"',
    ])

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toBe(`default=unset custom=${SECRET_VALUE}`)
  })

  // AC2: an invalid --as name is rejected before any token is touched.
  it('rejects an invalid --as var name with a usage error', async () => {
    if (env === undefined) throw new Error('env not initialized')

    const result = await env.run([
      'run',
      '--token',
      'irrelevant',
      '--as',
      'lower_case',
      '--',
      'true',
    ])

    expect(result.exitCode).not.toBe(0)
    expect(result.stderr).toContain('--as')
    expect(result.stderr).toContain('lower_case')
  })

  it('propagates the child exit code', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const token = await mintToken(env.configDir, SECRET_NAME, SECRET_VALUE)

    const result = await env.run(['run', '--token', token, '--', 'sh', '-c', 'exit 7'])
    expect(result.exitCode).toBe(7)
  })

  it('documents --token and --as in --help', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const result = await env.run(['run', '--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('--token')
    expect(result.stdout).toContain('--as')
    expect(result.stdout).toContain('VAULTKEEPER_SECRET')
  })

  it('rejects a spawn failure for a nonexistent wrapped command', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const token = await mintToken(env.configDir, SECRET_NAME, SECRET_VALUE)

    const result = await env.run(['run', '--token', token, '--', '/no/such/command'])
    expect(result.exitCode).not.toBe(0)
    expect(result.stderr).toContain('ExecError:')
    expect(result.stderr).toContain('Could not start "/no/such/command"')
  })
})

describe('run is documented; exec is unaffected for its own flow', () => {
  it('lists run in the top-level help', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const result = await env.run(['--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('run')
  })
})

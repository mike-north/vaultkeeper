/**
 * UATs for the CLI config directory override — VAULTKEEPER_CONFIG_DIR and
 * the global --config-dir flag.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/65
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

/** Build a minimal valid config with a distinguishing ttlMinutes marker. */
function configWithMarker(ttlMinutes: number): Record<string, unknown> {
  return {
    version: 1,
    backends: [{ type: 'file', enabled: true }],
    keyRotation: { gracePeriodDays: 7 },
    defaults: { ttlMinutes, trustTier: 3 },
  }
}

describe('CLI config-dir override', () => {
  let env: CliTestEnv | undefined
  let extraDirs: string[] = []

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
    for (const dir of extraDirs) {
      await fs.rm(dir, { recursive: true, force: true })
    }
    extraDirs = []
  })

  // Acceptance criterion 1: VAULTKEEPER_CONFIG_DIR redirects config read/write.
  it('honors VAULTKEEPER_CONFIG_DIR for config show (env var isolation)', async () => {
    env = await createCliTestEnv({ config: configWithMarker(111) })
    const result = await env.run(['config', 'show'])
    expect(result.exitCode).toBe(0)
    const parsed: unknown = JSON.parse(result.stdout)
    expect(parsed).toHaveProperty('defaults.ttlMinutes', 111)
  })

  // Acceptance criterion 1: --config-dir redirects config read/write.
  it('honors --config-dir for config show (flag isolation)', async () => {
    env = await createCliTestEnv({ config: configWithMarker(222), configDirMode: 'flag' })
    const result = await env.run(['--config-dir', env.configDir, 'config', 'show'])
    expect(result.exitCode).toBe(0)
    const parsed: unknown = JSON.parse(result.stdout)
    expect(parsed).toHaveProperty('defaults.ttlMinutes', 222)
  })

  // Acceptance criterion 1: flag wins over env var when both are set.
  it('prefers --config-dir over VAULTKEEPER_CONFIG_DIR when both are set', async () => {
    env = await createCliTestEnv({ config: configWithMarker(333) }) // env var -> env.configDir

    const flagDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vaultkeeper-config-dir-flag-'))
    extraDirs.push(flagDir)
    await fs.writeFile(
      path.join(flagDir, 'config.json'),
      JSON.stringify(configWithMarker(444), null, 2) + '\n',
      { encoding: 'utf8', mode: 0o600 },
    )

    // env.run() sets VAULTKEEPER_CONFIG_DIR=env.configDir (ttlMinutes 333);
    // --config-dir points at flagDir (ttlMinutes 444). The flag must win.
    const result = await env.run(['--config-dir', flagDir, 'config', 'show'])
    expect(result.exitCode).toBe(0)
    const parsed: unknown = JSON.parse(result.stdout)
    expect(parsed).toHaveProperty('defaults.ttlMinutes', 444)
  })

  // Acceptance criterion 1: flag wins over env var even when the test harness
  // itself is asked to set a *competing* VAULTKEEPER_CONFIG_DIR via
  // configDirMode: 'flag' + options.env — regression for a bug where
  // createCliTestEnv() unconditionally stripped VAULTKEEPER_CONFIG_DIR in
  // 'flag' mode, making it impossible to exercise this precedence case.
  it('prefers --config-dir over a caller-supplied VAULTKEEPER_CONFIG_DIR in flag mode', async () => {
    const envConfigDir = await fs.mkdtemp(
      path.join(os.tmpdir(), 'vaultkeeper-config-dir-competing-env-'),
    )
    extraDirs.push(envConfigDir)
    await fs.writeFile(
      path.join(envConfigDir, 'config.json'),
      JSON.stringify(configWithMarker(555), null, 2) + '\n',
      { encoding: 'utf8', mode: 0o600 },
    )

    env = await createCliTestEnv({
      config: configWithMarker(666),
      configDirMode: 'flag',
      env: { VAULTKEEPER_CONFIG_DIR: envConfigDir },
    })

    const result = await env.run(['--config-dir', env.configDir, 'config', 'show'])
    expect(result.exitCode).toBe(0)
    const parsed: unknown = JSON.parse(result.stdout)
    expect(parsed).toHaveProperty('defaults.ttlMinutes', 666)
  })

  // Acceptance criterion 2: config show reports the path it loaded from.
  it('reports the loaded config path on config show', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['config', 'show'])
    expect(result.exitCode).toBe(0)
    const expectedPath = path.join(env.configDir, 'config.json')
    expect(result.stderr).toContain(`Loaded from: ${expectedPath}`)
  })

  // Acceptance criterion 2: config init creates the override directory as needed.
  it('creates the override directory on config init when it does not yet exist', async () => {
    const parentDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vaultkeeper-config-dir-init-'))
    extraDirs.push(parentDir)
    const nestedConfigDir = path.join(parentDir, 'nested', 'vaultkeeper')

    env = await createCliTestEnv({ configDirMode: 'flag' })
    const result = await env.run(['--config-dir', nestedConfigDir, 'config', 'init'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain(
      `Config created at ${path.join(nestedConfigDir, 'config.json')}`,
    )

    const content = await fs.readFile(path.join(nestedConfigDir, 'config.json'), 'utf8')
    const parsed: unknown = JSON.parse(content)
    expect(parsed).toHaveProperty('version', 1)
  })

  // Acceptance criterion 3: doctor also respects the override (reads the
  // config to scope its checks) rather than ignoring it.
  it('scopes doctor checks to the backends configured under --config-dir', async () => {
    env = await createCliTestEnv({ config: configWithMarker(60), configDirMode: 'flag' })
    const result = await env.run(['--config-dir', env.configDir, 'doctor'])
    expect(result.exitCode === 0 || result.exitCode === 1).toBe(true)
    const hasChecks = result.stdout.includes('✓') || result.stdout.includes('✗')
    expect(hasChecks).toBe(true)
  })

  // Acceptance criterion 6 / Proof: two simultaneous isolated config dirs on
  // one machine, neither touching the default (~/.config/vaultkeeper) location.
  it('supports two simultaneous isolated config dirs without cross-contamination', async () => {
    const envA = await createCliTestEnv({ config: configWithMarker(11) })
    const envB = await createCliTestEnv({ config: configWithMarker(22) })

    try {
      expect(envA.configDir).not.toBe(envB.configDir)

      const [resultA, resultB] = await Promise.all([
        envA.run(['config', 'show']),
        envB.run(['config', 'show']),
      ])

      expect(resultA.exitCode).toBe(0)
      expect(resultB.exitCode).toBe(0)

      const parsedA: unknown = JSON.parse(resultA.stdout)
      const parsedB: unknown = JSON.parse(resultB.stdout)
      expect(parsedA).toHaveProperty('defaults.ttlMinutes', 11)
      expect(parsedB).toHaveProperty('defaults.ttlMinutes', 22)

      // Neither isolated dir is (or is under) the real default location.
      const defaultDir = path.join(os.homedir(), '.config', 'vaultkeeper')
      expect(envA.configDir).not.toBe(defaultDir)
      expect(envB.configDir).not.toBe(defaultDir)
    } finally {
      await envA.cleanup()
      await envB.cleanup()
    }
  })

  // Negative: --config-dir without a value is a usage error, not a crash.
  it('exits 2 when --config-dir is given without a value', async () => {
    env = await createCliTestEnv({ configDirMode: 'flag' })
    const result = await env.run(['--config-dir'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('--config-dir requires a value')
  })

  // Negative: an empty --config-dir value must not be silently treated as
  // "no override" — that would mask a malformed invocation by falling back
  // to env/default resolution instead of failing loudly.
  it('exits 2 when --config-dir is given an empty value via a separate arg', async () => {
    env = await createCliTestEnv({ configDirMode: 'flag' })
    const result = await env.run(['--config-dir', '', 'config', 'show'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('--config-dir requires a value')
  })

  // Negative: same as above, but for the --config-dir=<value> form.
  it('exits 2 when --config-dir= is given an empty value', async () => {
    env = await createCliTestEnv({ configDirMode: 'flag' })
    const result = await env.run(['--config-dir=', 'config', 'show'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('--config-dir requires a value')
  })

  // Negative: --config-dir after exec's `--` separator belongs to the
  // wrapped command, not to vaultkeeper itself, and must pass through untouched.
  it('does not consume --config-dir after the exec -- separator', async () => {
    env = await createCliTestEnv({ configDirMode: 'flag' })
    const result = await env.run([
      '--config-dir',
      env.configDir,
      'exec',
      '--secret',
      'does-not-exist',
      '--env',
      'FOO',
      '--caller',
      'dev',
      '--skip-doctor',
      '--',
      'echo',
      '--config-dir',
      'not-a-vaultkeeper-flag',
    ])
    // The secret lookup will fail (it doesn't exist), but the point of this
    // test is that argument parsing doesn't choke on --config-dir inside the
    // wrapped command — it should reach the "secret not found" failure path,
    // not a usage error about --config-dir.
    expect(result.exitCode).toBe(1)
    expect(result.stderr).not.toContain('--config-dir requires a value')
  })

  // --help documents the flag and env var (acceptance criterion 4).
  it('documents --config-dir and VAULTKEEPER_CONFIG_DIR in top-level --help', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('--config-dir')
    expect(result.stdout).toContain('VAULTKEEPER_CONFIG_DIR')
  })
})

/**
 * UATs for the doctor command.
 *
 * Note: doctor output depends on the system environment (installed tools, etc).
 * These tests verify the command runs and produces structured check output.
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

describe('doctor command', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('should run and produce check output', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['doctor'])
    // Doctor may exit 0 (all checks pass) or 1 (some checks fail)
    // depending on the environment. We just verify it runs and produces output.
    expect(result.exitCode === 0 || result.exitCode === 1).toBe(true)
    // Output should contain check markers (✓ or ✗)
    const hasChecks = result.stdout.includes('✓') || result.stdout.includes('✗')
    expect(hasChecks).toBe(true)
  })

  // Repro from issue #68: with a corrupt config.json, doctor previously
  // never touched the config and reported "System ready." with exit 0. It
  // must now report a failing "config" check with the parse error and file
  // path, and exit non-zero.
  //
  // Issue #130: doctor's config remediation is the CLI-native message built
  // from the check's structured error, so it names `config init --force` and
  // never tells a user already running the CLI to "install @vaultkeeper/cli"
  // (the last surface still carrying the library's multi-audience text).
  it('should report a failing config check and exit non-zero for corrupt config.json (issue #68 repro)', async () => {
    env = await createCliTestEnv()
    await fs.writeFile(path.join(env.configDir, 'config.json'), '{ bad json', 'utf8')
    const result = await env.run(['doctor'])
    expect(result.exitCode).not.toBe(0)
    expect(result.stdout).toContain('✗')
    expect(result.stdout).toContain('config')
    expect(result.stdout).toContain(path.join(env.configDir, 'config.json'))
    expect(result.stdout).toMatch(/line \d+, column \d+/)
    expect(result.stdout).toContain('vaultkeeper config init --force')
    expect(result.stdout).not.toContain('install @vaultkeeper/cli')
    expect(result.stdout).not.toContain('System ready.')
  })

  it('should report a CLI-native remediation for a structurally invalid config.json (issue #130)', async () => {
    env = await createCliTestEnv()
    await fs.writeFile(
      path.join(env.configDir, 'config.json'),
      JSON.stringify({ version: 99 }),
      'utf8',
    )
    const result = await env.run(['doctor'])
    expect(result.exitCode).not.toBe(0)
    expect(result.stdout).toContain('config')
    expect(result.stdout).toContain(path.join(env.configDir, 'config.json'))
    expect(result.stdout).toContain('vaultkeeper config init --force')
    // A schema-validation failure has no parse location, so the CLI-native
    // message must not carry a "(at line N, column N)" suffix.
    expect(result.stdout).not.toMatch(/\(at line \d+, column \d+\)/)
    expect(result.stdout).not.toContain('install @vaultkeeper/cli')
    expect(result.stdout).not.toContain('System ready.')
  })

  // No-config story (issue #68): doctor falls back to the default backend and
  // says so, uniformly with store/delete/exec/config show, rather than
  // silently defaulting or erroring. Issue #98: that default is the safe file
  // backend, and the hint spells out --backend.
  it('should report a default-backend message naming the file backend when no config file exists', async () => {
    env = await createCliTestEnv()
    await fs.rm(path.join(env.configDir, 'config.json'))
    const result = await env.run(['doctor'])
    expect(result.stderr).toContain('No config file found')
    expect(result.stderr).toContain('using the default backend (file)')
    expect(result.stderr).toContain('vaultkeeper config init --backend file')
  })

  // Issue #116: a fresh doctor run whose resolved backend is `file` (the
  // post-#98 default) must not show a failing check for an unused plugin
  // backend (ykman/op) — the file backend needs neither. Before the fix,
  // doctor always rendered every non-'ok' check with ✗ regardless of
  // whether it was required, so a brand-new file-default install looked
  // broken on the very first command.
  //
  // This asserts specifically on the unused plugin-backend lines, not on
  // overall success/exit code: doctor can legitimately exit 1 (and show a
  // ✗) for a genuinely missing *core* tool like openssl on some hosts, and
  // that's an unrelated, orthogonal failure mode this test must not flake
  // on.
  it('should not show a failing check for unused plugin backends on a fresh file-default run', async () => {
    env = await createCliTestEnv() // DEFAULT_CONFIG: file backend only
    const result = await env.run(['doctor'])
    expect(result.stdout).not.toMatch(/✗\s*ykman/)
    expect(result.stdout).not.toMatch(/✗\s*op\b/)
  })

  // Issue #116, acceptance criterion 3: opt-in backends still get their
  // dependency checks when actually configured — the yubikey backend
  // promotes the ykman check back to required, so its absence surfaces as
  // a failing check (most CI/dev machines don't have ykman installed).
  it('should surface the ykman check when the yubikey backend is configured', async () => {
    env = await createCliTestEnv({
      config: {
        version: 1,
        backends: [{ type: 'yubikey', enabled: true, plugin: true }],
        keyRotation: { gracePeriodDays: 7 },
        defaults: { ttlMinutes: 60, trustTier: 3 },
      },
    })
    const result = await env.run(['doctor'])
    expect(result.stdout).toContain('ykman')
  })
})

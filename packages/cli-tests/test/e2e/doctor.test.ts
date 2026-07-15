/**
 * UATs for the doctor command.
 *
 * Note: doctor output depends on the system environment (installed tools, etc).
 * These tests verify the command runs and produces structured check output.
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliResult, CliTestEnv } from '@vaultkeeper/cli-test-helpers'

/**
 * Tokenize a POSIX shell command into argv, honoring the exact quoting
 * `shellQuote` produces (whole values wrapped in single quotes, an embedded
 * single quote escaped as `'\''`). Used to run the LITERAL command `doctor`
 * prints — parsing its real output rather than re-deriving the args — so the
 * UAT proves the printed string works verbatim (issue #149).
 */
function parseShellCommand(cmd: string): string[] {
  const tokens: string[] = []
  let cur = ''
  let hasCur = false
  let i = 0
  while (i < cmd.length) {
    const c = cmd[i]
    if (c === undefined) {
      break
    }
    if (c === ' ' || c === '\t') {
      if (hasCur) {
        tokens.push(cur)
        cur = ''
        hasCur = false
      }
      i++
      continue
    }
    if (c === "'") {
      hasCur = true
      i++
      for (let q = cmd[i]; q !== undefined && q !== "'"; q = cmd[i]) {
        cur += q
        i++
      }
      i++ // skip the closing quote
      continue
    }
    if (c === '\\') {
      hasCur = true
      i++
      const escaped = cmd[i]
      if (escaped !== undefined) {
        cur += escaped
        i++
      }
      continue
    }
    hasCur = true
    cur += c
    i++
  }
  if (hasCur) {
    tokens.push(cur)
  }
  return tokens
}

/** Extract the copy-pasteable recovery command from a remediation sentence. */
function extractRemediationCommand(output: string): string {
  const match = /run `([^`]+)` to overwrite it/.exec(output)
  if (match?.[1] === undefined) {
    throw new Error(`No remediation command found in output:\n${output}`)
  }
  return match[1]
}

/**
 * Run the LITERAL command `doctor` printed, in a fresh process with NO
 * `--config-dir` flag supplied by the harness and NO `VAULTKEEPER_CONFIG_DIR`
 * env var — only whatever the printed command itself carries. `home` isolates
 * the platform-default config dir so the test can prove nothing was written
 * there. Maps the printed `vaultkeeper` token onto the test CLI entry point.
 */
async function runPrintedCommandFresh(printedCommand: string, home: string): Promise<CliResult> {
  const argv = parseShellCommand(printedCommand)
  expect(argv[0]).toBe('vaultkeeper')
  const runner = await createCliTestEnv({ configDirMode: 'flag', env: { HOME: home } })
  try {
    return await runner.run(argv.slice(1))
  } finally {
    await runner.cleanup()
  }
}

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

// Issue #149: the printed recovery command must repair the exact diagnosed
// file even when a non-default config dir is active. Issue #152: it must be
// printed exactly once. Both share the same doctor output surface.
describe('doctor config remediation targets the active dir and prints once (issues #149, #152)', () => {
  let home: string | undefined
  const cleanups: (() => Promise<void>)[] = []

  afterEach(async () => {
    for (const c of cleanups.splice(0)) {
      await c()
    }
    if (home !== undefined) {
      await fs.rm(home, { recursive: true, force: true })
      home = undefined
    }
  })

  it('prints a working --config-dir command for a --config-dir (flag) case, and repairs the file verbatim', async () => {
    home = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-home-flag-'))
    const env = await createCliTestEnv({ configDirMode: 'flag', env: { HOME: home } })
    cleanups.push(() => env.cleanup())

    // Seed a broken config under the non-default (flag) dir.
    const configPath = path.join(env.configDir, 'config.json')
    await fs.writeFile(configPath, 'not json', 'utf8')

    const doctor = await env.run(['doctor', '--config-dir', env.configDir])
    expect(doctor.exitCode).not.toBe(0)

    // The printed command must carry an explicit --config-dir for the
    // diagnosed dir (bare `config init --force` would target the default).
    const command = extractRemediationCommand(doctor.stdout)
    expect(command).toContain(`--config-dir '${env.configDir}'`)

    // Run the LITERAL printed command in a fresh process with no flag/env.
    const fix = await runPrintedCommandFresh(command, home)
    expect(fix.exitCode).toBe(0)

    // The diagnosed file is now valid JSON with a real config shape.
    const repairedRaw = await fs.readFile(configPath, 'utf8')
    const repaired: unknown = JSON.parse(repairedRaw)
    if (typeof repaired !== 'object' || repaired === null || !('backends' in repaired)) {
      throw new Error(`repaired config is not a config object: `)
    }
    expect(Array.isArray(repaired.backends)).toBe(true)

    // No config was created at the platform default location as a side effect.
    const defaultConfig = path.join(home, '.config', 'vaultkeeper', 'config.json')
    await expect(fs.access(defaultConfig)).rejects.toThrow()
  })

  it('prints a working --config-dir command for a VAULTKEEPER_CONFIG_DIR-only case', async () => {
    home = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-home-env-'))
    // env-mode: the active dir comes ONLY from VAULTKEEPER_CONFIG_DIR.
    const env = await createCliTestEnv({ configDirMode: 'env', env: { HOME: home } })
    cleanups.push(() => env.cleanup())

    const configPath = path.join(env.configDir, 'config.json')
    await fs.writeFile(configPath, 'not json', 'utf8')

    const doctor = await env.run(['doctor'])
    expect(doctor.exitCode).not.toBe(0)

    // Even though the dir came from the env var, the printed command must
    // carry --config-dir so a fresh shell (which won't have the env var set)
    // still repairs the right file.
    const command = extractRemediationCommand(doctor.stdout)
    expect(command).toContain(`--config-dir '${env.configDir}'`)

    // Fresh process: no VAULTKEEPER_CONFIG_DIR, only the printed --config-dir.
    const fix = await runPrintedCommandFresh(command, home)
    expect(fix.exitCode).toBe(0)

    const repairedRaw = await fs.readFile(configPath, 'utf8')
    const repaired: unknown = JSON.parse(repairedRaw)
    if (typeof repaired !== 'object' || repaired === null || !('backends' in repaired)) {
      throw new Error(`repaired config is not a config object: `)
    }
    expect(Array.isArray(repaired.backends)).toBe(true)

    const defaultConfig = path.join(home, '.config', 'vaultkeeper', 'config.json')
    await expect(fs.access(defaultConfig)).rejects.toThrow()
  })

  it('prints the remediation sentence exactly once for an invalid config (issue #152)', async () => {
    home = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-home-once-'))
    const env = await createCliTestEnv({ configDirMode: 'flag', env: { HOME: home } })
    cleanups.push(() => env.cleanup())

    await fs.writeFile(path.join(env.configDir, 'config.json'), 'not json', 'utf8')

    const doctor = await env.run(['doctor', '--config-dir', env.configDir])
    expect(doctor.exitCode).not.toBe(0)

    // The remediation (both the sentence stem and its command) appears once.
    const sentences = doctor.stdout.split('The config at').length - 1
    expect(sentences).toBe(1)
    const commands = doctor.stdout.split('config init --force').length - 1
    expect(commands).toBe(1)

    // ...and it lives under "Next steps", not inline on the ✗ config check.
    const nextStepsIdx = doctor.stdout.indexOf('Next steps:')
    expect(nextStepsIdx).toBeGreaterThanOrEqual(0)
    expect(doctor.stdout.indexOf('config init --force')).toBeGreaterThan(nextStepsIdx)
  })
})

/**
 * UATs for the config init/show lifecycle.
 *
 * These tests verify the config command works with an isolated config dir
 * via VAULTKEEPER_CONFIG_DIR. Each maps to an acceptance criterion of the
 * backend-selection UX work: choosing a backend, rejecting typos in flags
 * and backend values, keeping the platform default, and surfacing the
 * resolved active backend.
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

/**
 * The backend type `config init` writes when no `--backend` is given. Issue
 * #98: this is the safe `file` backend on every platform — never the OS-native
 * store — so a copy-pasted `config init` can't silently target the real
 * keychain.
 */
const defaultBackend = 'file'

describe('config command', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  /** Create an env and remove the config.json that createCliTestEnv seeds. */
  async function freshEnv(): Promise<CliTestEnv> {
    const created = await createCliTestEnv()
    await fs.rm(path.join(created.configDir, 'config.json'))
    return created
  }

  async function readConfig(dir: string): Promise<unknown> {
    const content = await fs.readFile(path.join(dir, 'config.json'), 'utf8')
    return JSON.parse(content)
  }

  it('should show config and exit 0 when config.json exists', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['config', 'show'])
    expect(result.exitCode).toBe(0)
    const parsed: unknown = JSON.parse(result.stdout)
    expect(parsed).toHaveProperty('version', 1)
    expect(parsed).toHaveProperty('backends')
  })

  it('should exit 1 for config init when config already exists', async () => {
    env = await createCliTestEnv()
    // createCliTestEnv already writes config.json
    const result = await env.run(['config', 'init'])
    expect(result.exitCode).toBe(1)
    expect(result.stderr).toContain('already exists')
  })

  it('should create config with config init when no config exists', async () => {
    env = await freshEnv()
    const result = await env.run(['config', 'init'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Config created at')
    const parsed = await readConfig(env.configDir)
    expect(parsed).toHaveProperty('version', 1)
  })

  // Criterion 3 (issue #98): without --backend, config init writes the safe
  // file default — never the OS-native store — on every platform.
  it('should generate the safe file default for config init with no --backend', async () => {
    env = await freshEnv()
    const result = await env.run(['config', 'init'])
    expect(result.exitCode).toBe(0)
    const parsed = await readConfig(env.configDir)
    expect(parsed).toHaveProperty('backends[0].type', defaultBackend)
  })

  // Criterion 3: init states which backend was configured and how to change it.
  it('should report the configured backend and how to change it on default init', async () => {
    env = await freshEnv()
    const result = await env.run(['config', 'init'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain(`Backend: ${defaultBackend}`)
    // Every default-init message points the user at the override flag.
    expect(result.stdout).toContain('--backend')
  })

  // Criterion 1: --backend <type> writes a config whose first enabled backend
  // is <type>.
  it('should write the file backend when config init --backend file is used', async () => {
    env = await freshEnv()
    const result = await env.run(['config', 'init', '--backend', 'file'])
    expect(result.exitCode).toBe(0)
    const parsed = await readConfig(env.configDir)
    expect(parsed).toHaveProperty('backends[0].type', 'file')
    expect(parsed).toHaveProperty('backends[0].enabled', true)
    expect(result.stdout).toContain('Backend: file')
  })

  // Criterion 1: an unknown backend value exits 2 listing valid types.
  it('should exit 2 for config init with an unknown backend value', async () => {
    env = await freshEnv()
    const result = await env.run(['config', 'init', '--backend', 'nope'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain("unknown backend type 'nope'")
    // The error lists valid backend types so the user can correct the typo.
    expect(result.stderr).toContain('file')
    // Nothing should have been written.
    await expect(fs.access(path.join(env.configDir, 'config.json'))).rejects.toThrow()
  })

  // Criterion 2: a typo in a flag on config init must never be silently ignored
  // (it could route secrets to the wrong credential store).
  it('should exit 2 for config init with an unknown flag', async () => {
    env = await freshEnv()
    const result = await env.run(['config', 'init', '--bakcend', 'file'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr.toLowerCase()).toContain('unknown option')
    // The typo must not have silently written a (default keychain) config.
    await expect(fs.access(path.join(env.configDir, 'config.json'))).rejects.toThrow()
  })

  // Criterion 2: unknown flags on config show also exit 2.
  it('should exit 2 for config show with an unknown flag', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['config', 'show', '--nope'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr.toLowerCase()).toContain('unknown option')
  })

  // Criterion 4: config show reports the resolved active backend.
  it('should report the resolved active backend on config show', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['config', 'show'])
    expect(result.exitCode).toBe(0)
    // stdout stays valid JSON; the active backend is annotated on stderr.
    const parsed: unknown = JSON.parse(result.stdout)
    expect(parsed).toHaveProperty('backends[0].type', 'file')
    expect(result.stderr).toContain('Active backend: file')
  })

  // Criterion 7 / Proof: init --backend file then show, end-to-end.
  it('should demonstrate the file backend end-to-end (init --backend file then show)', async () => {
    env = await freshEnv()
    const initResult = await env.run(['config', 'init', '--backend', 'file'])
    expect(initResult.exitCode).toBe(0)

    const showResult = await env.run(['config', 'show'])
    expect(showResult.exitCode).toBe(0)
    const parsed: unknown = JSON.parse(showResult.stdout)
    expect(parsed).toHaveProperty('backends[0].type', 'file')
    expect(showResult.stderr).toContain('Active backend: file')
  })

  // No-config story (issue #68): commands that need config fall back to
  // platform defaults and say so, rather than erroring. `config show`
  // previously exited 1 with "No config file found"; it now exits 0,
  // prints the resolved defaults, and reports the fallback on stderr — the
  // same story store/delete/exec/doctor use.
  it('should exit 0 and print platform defaults for config show when no config exists (regression: issue #68 uniform no-config story)', async () => {
    env = await freshEnv()
    const result = await env.run(['config', 'show'])
    expect(result.exitCode).toBe(0)
    const parsed: unknown = JSON.parse(result.stdout)
    expect(parsed).toHaveProperty('version', 1)
    expect(parsed).toHaveProperty('backends[0].type', defaultBackend)
    expect(result.stderr).toContain('No config file found')
    expect(result.stderr).toContain('using the default backend (file)')
    expect(result.stderr).toContain('vaultkeeper config init --backend file')
  })

  // Repro from issue #68: a syntactically invalid config.json must never be
  // dumped verbatim with exit 0 — it must fail with the parse error, the
  // file path, a parse location, and a remediation hint.
  //
  // Issue #114: the remediation hint must be CLI-native ("run `vaultkeeper
  // config init --force`"), not the library's "install @vaultkeeper/cli"
  // text — a user running this CLI already has it installed. The library's
  // own field-level validation reason (e.g. "version must be 1") is no
  // longer echoed verbatim, since it travels only inside the library's
  // message alongside that wrong remediation (issue #100); the CLI instead
  // builds its own message from the error's structured, remediation-free
  // fields (path, and — for a parse error — its line/column location).
  it('should exit non-zero with path, parse location, and remediation hint for corrupt config.json (issue #68 repro)', async () => {
    env = await createCliTestEnv()
    await fs.writeFile(path.join(env.configDir, 'config.json'), '{ bad json', 'utf8')
    const result = await env.run(['config', 'show'])
    expect(result.exitCode).not.toBe(0)
    expect(result.stdout).toBe('')
    expect(result.stderr).toContain(path.join(env.configDir, 'config.json'))
    expect(result.stderr).toMatch(/line \d+, column \d+/)
    expect(result.stderr).toContain('vaultkeeper config init --force')
    expect(result.stderr).not.toContain('install @vaultkeeper/cli')
  })

  it('should exit non-zero with path and remediation hint for a structurally invalid config.json', async () => {
    env = await createCliTestEnv()
    await fs.writeFile(
      path.join(env.configDir, 'config.json'),
      JSON.stringify({ version: 99 }),
      'utf8',
    )
    const result = await env.run(['config', 'show'])
    expect(result.exitCode).not.toBe(0)
    expect(result.stderr).toContain(path.join(env.configDir, 'config.json'))
    expect(result.stderr).toContain('vaultkeeper config init --force')
    expect(result.stderr).not.toContain('install @vaultkeeper/cli')
  })

  // Issue #137: an unreadable config.json (chmod 000, simulating EACCES/EPERM
  // in the wild — e.g. a root-owned config) is a third config-error path that
  // #114/#129 didn't cover, since it's a FilesystemError rather than
  // ConfigParseError/ConfigValidationError. The CLI must still name the
  // config path and never recommend `config init --force` — that command
  // would hit the exact same permission error trying to write the
  // replacement file, so it's a dead end here (unlike the parse/validation
  // cases, where it's the documented recovery). Skipped on Windows (chmod
  // semantics differ) and when running as root (root bypasses the
  // permission bits entirely, so the repro wouldn't reproduce EACCES).
  const isWindows = process.platform === 'win32'
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0
  describe.skipIf(isWindows || isRoot)('unreadable config.json (issue #137)', () => {
    it('names the config path, suggests checking permissions, and never suggests install/force-reinit', async () => {
      env = await createCliTestEnv()
      const configPath = path.join(env.configDir, 'config.json')
      await fs.chmod(configPath, 0o000)

      const result = await env.run(['config', 'show'])

      expect(result.exitCode).not.toBe(0)
      expect(result.stdout).toBe('')
      expect(result.stderr).toContain(configPath)
      expect(result.stderr).not.toContain('install @vaultkeeper/cli')
      expect(result.stderr).not.toContain('config init --force')
      expect(result.stderr.toLowerCase()).toContain('permission')
    })
  })

  it('should exit 2 for config with no subcommand', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['config'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain('Usage: vaultkeeper config')
  })

  // Issue #97: a corrupt config.json previously had no CLI recovery path —
  // `config init` refused to overwrite it, so the error's own remediation
  // ("run config init") was a dead end. `config init --force` is the
  // supported recovery command; this exercises the full corrupt -> recover
  // -> show flow end-to-end.
  describe('config init --force recovery (issue #97)', () => {
    it('should refuse to overwrite an existing config without --force (regression: issue #97 dead-end remediation)', async () => {
      env = await createCliTestEnv()
      const result = await env.run(['config', 'init'])
      expect(result.exitCode).toBe(1)
      expect(result.stderr).toContain('already exists')
      // The refusal itself must point at the working recovery command.
      expect(result.stderr).toContain('vaultkeeper config init --force')
    })

    it('should recover from a corrupt config.json via config init --force, then config show succeeds (issue #97 repro)', async () => {
      env = await createCliTestEnv()
      await fs.writeFile(path.join(env.configDir, 'config.json'), '{ not valid json', 'utf8')

      // Confirm the corruption is detected first (issue #68 behavior).
      const broken = await env.run(['config', 'show'])
      expect(broken.exitCode).not.toBe(0)

      // The documented recovery command succeeds over the corrupt file.
      const recover = await env.run(['config', 'init', '--force'])
      expect(recover.exitCode).toBe(0)
      expect(recover.stdout).toContain('Config created at')

      // And config show now succeeds against the recovered config.
      const recovered = await env.run(['config', 'show'])
      expect(recovered.exitCode).toBe(0)
      const parsed: unknown = JSON.parse(recovered.stdout)
      expect(parsed).toHaveProperty('version', 1)
    })

    it('should overwrite a valid existing config with config init --force', async () => {
      env = await createCliTestEnv()
      const before = await readConfig(env.configDir)
      expect(before).toHaveProperty('backends[0].type', 'file')

      const result = await env.run(['config', 'init', '--force', '--backend', defaultBackend])
      expect(result.exitCode).toBe(0)
      const after = await readConfig(env.configDir)
      expect(after).toHaveProperty('backends[0].type', defaultBackend)
    })

    // Criterion 4: --backend interaction is preserved under --force.
    it('should honor --backend when combined with --force (config init --force --backend file)', async () => {
      env = await createCliTestEnv()
      await fs.writeFile(path.join(env.configDir, 'config.json'), '{ still not valid json', 'utf8')

      const result = await env.run(['config', 'init', '--force', '--backend', 'file'])
      expect(result.exitCode).toBe(0)
      const parsed = await readConfig(env.configDir)
      expect(parsed).toHaveProperty('backends[0].type', 'file')
      expect(result.stdout).toContain('Backend: file')
    })

    // Criterion 3: ConfigParseError's remediation text names a command that
    // actually works in the state that produced the error.
    it('should have ConfigParseError name the working recovery command (regression: issue #97)', async () => {
      env = await createCliTestEnv()
      await fs.writeFile(path.join(env.configDir, 'config.json'), '{ bad json', 'utf8')
      const result = await env.run(['config', 'show'])
      expect(result.exitCode).not.toBe(0)
      expect(result.stderr).toContain('vaultkeeper config init --force')

      // And that named command must actually succeed from this exact state.
      const recover = await env.run(['config', 'init', '--force'])
      expect(recover.exitCode).toBe(0)
    })

    // Criterion 3, ConfigValidationError variant: structurally valid JSON
    // that fails schema validation shares the same remediation hint as
    // ConfigParseError, so it must also name the working recovery command.
    it('should have ConfigValidationError name the working recovery command (regression: issue #97)', async () => {
      env = await createCliTestEnv()
      await fs.writeFile(
        path.join(env.configDir, 'config.json'),
        JSON.stringify({ version: 99 }),
        'utf8',
      )
      const result = await env.run(['config', 'show'])
      expect(result.exitCode).not.toBe(0)
      expect(result.stderr).toContain('vaultkeeper config init --force')

      // And that named command must actually succeed from this exact state.
      const recover = await env.run(['config', 'init', '--force'])
      expect(recover.exitCode).toBe(0)
    })
  })
})

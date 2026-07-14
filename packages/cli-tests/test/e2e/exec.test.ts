/**
 * UATs for the exec command's TOFU trust gate — the real CLI subprocess
 * contract with non-TTY stdin.
 *
 * The definitive proof for "trusted callers are not re-prompted": once the
 * caller's hash is in the trust manifest, exec must proceed WITHOUT an
 * interactive prompt. Because these run with a piped (non-TTY) stdin, any code
 * path that reached the interactive prompt would fail — so a clean exit proves
 * the prompt was skipped, and a prompt-required failure proves it was not.
 *
 * Secrets use the file backend under an isolated HOME so no OS credential
 * store is touched.
 *
 * Issue #58 (non-interactive exec) adds coverage for the CI escape hatches:
 * `--yes` and `VAULTKEEPER_YES` approve an untrusted caller without a prompt and
 * record the approval, and an untrusted caller on non-TTY stdin fails with
 * actionable remediation.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/57
 * @see https://github.com/mike-north/vaultkeeper/issues/58
 */
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

const SECRET_NAME = 'API_KEY'
const SECRET_VALUE = 's3cr3t-value'

let env: CliTestEnv | undefined
let homeDir: string

beforeEach(async () => {
  homeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-exec-home-'))
  env = await createCliTestEnv({
    env: { HOME: homeDir, VAULTKEEPER_SKIP_DOCTOR: '1' },
  })
  // Store the secret in the file backend (rooted at the isolated HOME).
  const stored = await env.runWithStdin(['store', '--name', SECRET_NAME], `${SECRET_VALUE}\n`)
  expect(stored.exitCode).toBe(0)
})

afterEach(async () => {
  if (env !== undefined) {
    await env.cleanup()
    env = undefined
  }
  await fs.rm(homeDir, { recursive: true, force: true })
})

async function writeCaller(contents: string): Promise<string> {
  const caller = path.join(homeDir, 'caller.sh')
  await fs.writeFile(caller, contents, { mode: 0o755 })
  return caller
}

function execArgs(caller: string, extraFlags: string[] = []): string[] {
  return [
    'exec',
    '--secret',
    SECRET_NAME,
    '--env',
    'INJECTED',
    '--caller',
    caller,
    // Extra exec flags must go BEFORE the `--` separator, or they would be
    // parsed as part of the wrapped command instead of as exec options.
    ...extraFlags,
    '--',
    'sh',
    '-c',
    'printf "ready=%s" "${INJECTED:+yes}"',
  ]
}

describe('exec trust gate', () => {
  // Issue #57 criterion 3 / issue #58 criterion 1: after approve, a trusted
  // caller runs exec with NO prompt on non-TTY stdin, reporting a trusted state.
  it('does not prompt for an approved caller and injects the secret', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const caller = await writeCaller('#!/bin/sh\necho hi\n')

    const approved = await env.run(['approve', '--script', caller])
    expect(approved.exitCode).toBe(0)

    const result = await env.run(execArgs(caller))
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('ready=yes')
    expect(result.stderr).toContain('Trust: verified')
    expect(result.stderr).not.toContain('Pending verification')
    expect(result.stderr).not.toMatch(/Allow\?|\[y\/N\]/)
  })

  // Criterion 4 (observable CLI outcome): repeated exec invocations with the
  // same, unmodified approved caller never re-prompt.
  it('does not re-prompt on subsequent invocations of the same caller', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const caller = await writeCaller('#!/bin/sh\necho hi\n')
    await env.run(['approve', '--script', caller])

    const first = await env.run(execArgs(caller))
    const second = await env.run(execArgs(caller))
    expect(first.exitCode).toBe(0)
    expect(second.exitCode).toBe(0)
    expect(second.stderr).toContain('Trust: verified')
    expect(second.stderr).not.toMatch(/Allow\?|\[y\/N\]/)
  })

  // Criterion 5: a caller modified after approval is NOT silently trusted. A
  // hash mismatch fails directly with an identity-mismatch error and re-approval
  // guidance (no interactive prompt, since setup() would reject the same hash
  // conflict regardless of the answer), never reporting a verified state.
  it('rejects a modified caller with an identity-mismatch error (no silent trust inheritance)', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const caller = await writeCaller('#!/bin/sh\necho original\n')
    await env.run(['approve', '--script', caller])

    // Tamper with the caller after approval — its hash no longer matches.
    await fs.writeFile(caller, '#!/bin/sh\necho tampered\n', { mode: 0o755 })

    const result = await env.run(execArgs(caller))
    expect(result.exitCode).not.toBe(0)
    expect(result.stderr).not.toContain('Trust: verified')
    // Fails on the hash mismatch, not the interactive prompt.
    expect(result.stderr).not.toContain('interactive approval')
    expect(result.stderr).toContain('has changed since it was approved')
    expect(result.stderr).toContain(`vaultkeeper approve --script ${caller}`)
    expect(result.stdout).not.toContain('ready=yes')
  })

  // Issue #58, criterion 3: a never-approved caller on non-TTY stdin fails, but
  // the error tells the user exactly how to proceed non-interactively — pre-approve
  // with `approve --script`, or re-run with --yes / VAULTKEEPER_YES.
  it('fails an untrusted caller on non-TTY stdin with actionable remediation', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const caller = await writeCaller('#!/bin/sh\necho hi\n')

    const result = await env.run(execArgs(caller))
    expect(result.exitCode).not.toBe(0)
    expect(result.stderr).not.toContain('Trust: verified')
    expect(result.stdout).not.toContain('ready=yes')
    expect(result.stderr).toContain(`vaultkeeper approve --script ${caller}`)
    expect(result.stderr).toContain('--yes')
    expect(result.stderr).toContain('VAULTKEEPER_YES=1')
  })

  // Issue #58, criterion 2: --yes approves an untrusted caller non-interactively
  // (non-TTY stdin) AND records the approval, so a later exec without --yes is
  // trusted and needs no prompt.
  it('approves an untrusted caller with --yes and records trust for later runs', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const caller = await writeCaller('#!/bin/sh\necho hi\n')

    const first = await env.run(execArgs(caller, ['--yes']))
    expect(first.exitCode).toBe(0)
    expect(first.stdout).toContain('ready=yes')
    expect(first.stderr).toContain('approved via --yes')
    expect(first.stderr).not.toMatch(/Allow\?|\[y\/N\]/)

    // The approval was recorded: a subsequent run WITHOUT --yes is trusted.
    const second = await env.run(execArgs(caller))
    expect(second.exitCode).toBe(0)
    expect(second.stdout).toContain('ready=yes')
    expect(second.stderr).toContain('Trust: verified')
  })

  // Issue #58, criterion 2: VAULTKEEPER_YES=1 is equivalent to --yes and records
  // the approval in the trust manifest.
  it('approves an untrusted caller via VAULTKEEPER_YES=1 and records it in the manifest', async () => {
    const yesEnv = await createCliTestEnv({
      env: { HOME: homeDir, VAULTKEEPER_SKIP_DOCTOR: '1', VAULTKEEPER_YES: '1' },
    })
    try {
      const stored = await yesEnv.runWithStdin(
        ['store', '--name', SECRET_NAME],
        `${SECRET_VALUE}\n`,
      )
      expect(stored.exitCode).toBe(0)

      const caller = path.join(homeDir, 'yes-env-caller.sh')
      await fs.writeFile(caller, '#!/bin/sh\necho hi\n', { mode: 0o755 })

      const result = await yesEnv.run(execArgs(caller))
      expect(result.exitCode).toBe(0)
      expect(result.stdout).toContain('ready=yes')
      expect(result.stderr).toContain('approved via --yes')
      expect(result.stderr).not.toMatch(/Allow\?|\[y\/N\]/)

      // The approval was recorded in the trust manifest under the caller's path.
      const manifestRaw = await fs.readFile(
        path.join(yesEnv.configDir, 'trust-manifest.json'),
        'utf8',
      )
      const manifest: unknown = JSON.parse(manifestRaw)
      if (
        typeof manifest !== 'object' ||
        manifest === null ||
        !('entries' in manifest) ||
        typeof manifest.entries !== 'object' ||
        manifest.entries === null
      ) {
        throw new Error('trust manifest missing entries object')
      }
      expect(Object.keys(manifest.entries)).toContain(path.resolve(caller))
    } finally {
      await yesEnv.cleanup()
    }
  })

  // Issue #58, criterion 4: exec --help documents the TTY requirement and both
  // escape hatches, proven against the real CLI subprocess.
  it('documents the TTY requirement and escape hatches in exec --help', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const result = await env.run(['exec', '--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('--yes')
    expect(result.stdout).toContain('VAULTKEEPER_YES')
    expect(result.stdout).toContain('non-TTY')
    expect(result.stdout).toContain('vaultkeeper approve --script')
  })
})

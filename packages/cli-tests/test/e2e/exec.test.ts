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
 * Issue #59 adds coverage for cross-process cached-token reuse (persisted key
 * material) and accurate error surfacing on the cached-token path: a revoked
 * key must be reported as `KeyRevokedError`, not a generic "expired" message.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/57
 * @see https://github.com/mike-north/vaultkeeper/issues/58
 * @see https://github.com/mike-north/vaultkeeper/issues/59
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
    // The path is shell-quoted so the suggested command is copy-paste safe.
    expect(result.stderr).toContain(`vaultkeeper approve --script '${caller}'`)
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
    // The path is shell-quoted so the suggested command is copy-paste safe.
    expect(result.stderr).toContain(`vaultkeeper approve --script '${caller}'`)
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

  // Issue #59, criterion 3 (definitive cross-process proof): two sequential
  // exec --cache invocations by the same trusted caller — separate node
  // subprocesses sharing the config dir and HOME. The second run reuses the
  // token cached by the first (persisted key material lets its kid still
  // resolve) and must NOT re-mint or print the "expired"/re-auth notice.
  it('reuses a cached token across processes without re-authenticating', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const caller = await writeCaller('#!/bin/sh\necho hi\n')
    await env.run(['approve', '--script', caller])

    const first = await env.run(execArgs(caller, ['--cache']))
    expect(first.exitCode).toBe(0)
    expect(first.stdout).toContain('ready=yes')

    const second = await env.run(execArgs(caller, ['--cache']))
    expect(second.exitCode).toBe(0)
    expect(second.stdout).toContain('ready=yes')
    expect(second.stderr).toContain('Trust: verified')
    // The cached token authorized cleanly — no re-mint, no misleading notice.
    expect(second.stderr).not.toContain('re-authenticating')
    expect(second.stderr).not.toContain('expired')
    expect(second.stderr).not.toContain('could not be authorized')
  })

  // Issue #59, criterion 4: when the key behind a cached token is revoked
  // between runs, the cached-token path reports the ACTUAL failure
  // (KeyRevokedError) rather than collapsing it into a generic "expired"
  // message, and still recovers by minting a fresh token for the trusted caller.
  it('surfaces KeyRevokedError (not "expired") when a cached token\'s key was revoked', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const caller = await writeCaller('#!/bin/sh\necho hi\n')
    await env.run(['approve', '--script', caller])

    // Mint and cache a token.
    const first = await env.run(execArgs(caller, ['--cache']))
    expect(first.exitCode).toBe(0)

    // Revoke the key — the cached token's kid is now unresolvable.
    const revoked = await env.run(['revoke-key'])
    expect(revoked.exitCode).toBe(0)

    const second = await env.run(execArgs(caller, ['--cache']))
    // Recovers (fresh mint for the trusted caller)…
    expect(second.exitCode).toBe(0)
    expect(second.stdout).toContain('ready=yes')
    // …but the notice names the real cause, not a bogus "expired".
    expect(second.stderr).toContain('KeyRevokedError')
    expect(second.stderr).not.toContain('Cached token expired')
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

  // Issue #69, criterion 3: exec validates secret existence BEFORE the
  // interactivity/TTY gate. Repro: a nonexistent secret with a NEVER-approved
  // caller on non-TTY stdin previously hit the trust gate first and reported
  // the generic "requires approval, but stdin is not a TTY" error, masking
  // the real problem. It must now report SecretNotFoundError-style messaging
  // regardless of TTY, and the caller must never be prompted or recorded.
  it('reports secret-not-found before the TTY/approval gate for a never-approved caller (issue #69 repro)', async () => {
    if (env === undefined) throw new Error('env not initialized')
    // A caller that has never been approved and is NOT pre-approved here —
    // if the trust gate ran first, this would fail with the TTY/approval
    // message instead of a secret-not-found error.
    const caller = await writeCaller('#!/bin/sh\necho hi\n')

    const result = await env.run(
      execArgs(caller).map((a) => (a === SECRET_NAME ? 'no-such-secret' : a)),
    )

    expect(result.exitCode).not.toBe(0)
    expect(result.stderr).toContain('SecretNotFoundError')
    expect(result.stderr).toContain('no-such-secret')
    expect(result.stderr).not.toContain('requires approval')
    expect(result.stderr).not.toContain('is not a TTY')
    expect(result.stderr).not.toMatch(/Allow\?|\[y\/N\]/)
  })

  // Complement: the same precondition check must not bypass or weaken the
  // trust gate for a caller that IS approved but the secret is missing.
  it('reports secret-not-found for an already-trusted caller too, without touching the wrapped command', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const caller = await writeCaller('#!/bin/sh\necho hi\n')
    const approved = await env.run(['approve', '--script', caller])
    expect(approved.exitCode).toBe(0)

    const result = await env.run(
      execArgs(caller).map((a) => (a === SECRET_NAME ? 'no-such-secret' : a)),
    )

    expect(result.exitCode).not.toBe(0)
    expect(result.stderr).toContain('SecretNotFoundError')
    expect(result.stdout).not.toContain('ready=')
  })
})

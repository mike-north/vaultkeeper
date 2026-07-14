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
 * @see https://github.com/mike-north/vaultkeeper/issues/57
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

function execArgs(caller: string): string[] {
  return [
    'exec',
    '--secret',
    SECRET_NAME,
    '--env',
    'INJECTED',
    '--caller',
    caller,
    '--',
    'sh',
    '-c',
    'printf "ready=%s" "${INJECTED:+yes}"',
  ]
}

describe('exec trust gate', () => {
  // Criterion 3: after approve, exec with a matching caller does NOT prompt
  // and reports a trusted state — proven on non-TTY stdin.
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

  // Criterion 3/5 contrast: an unapproved caller is also untrusted and reaches
  // the prompt gate (fails on non-TTY stdin).
  it('treats a never-approved caller as untrusted', async () => {
    if (env === undefined) throw new Error('env not initialized')
    const caller = await writeCaller('#!/bin/sh\necho hi\n')

    const result = await env.run(execArgs(caller))
    expect(result.exitCode).not.toBe(0)
    expect(result.stderr).not.toContain('Trust: verified')
    expect(result.stderr).toContain('interactive approval')
  })
})

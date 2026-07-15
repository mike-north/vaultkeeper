import { describe, it, expect, vi, beforeEach } from 'vitest'
import { delegatedExec } from '../../../src/access/delegated-exec.js'
import { ExecError } from '../../../src/errors.js'
import type { ExecRequest } from '../../../src/access/types.js'

// spawn is wrapped (not replaced) so every other test in this file still
// spawns real child processes — only the guardrail test below asserts
// against call count.
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>()
  return { ...actual, spawn: vi.fn(actual.spawn) }
})

import { spawn } from 'node:child_process'

const mockSpawn = vi.mocked(spawn)

beforeEach(() => {
  mockSpawn.mockClear()
})

describe('delegatedExec', () => {
  describe('args placeholder guardrail', () => {
    // Regression test for issue #70: {{secret}} in args was silently
    // substituted, exposing the plaintext secret on the process command
    // line (visible via `ps`). This must throw ExecError before spawning,
    // exactly like the command field does.
    it('rejects with ExecError when {{secret}} is used in args, without spawning', async () => {
      const request: ExecRequest = {
        command: 'echo',
        args: ['{{secret}}'],
        env: {},
      }

      const promise = delegatedExec('hello', request)

      await expect(promise).rejects.toThrow(ExecError)
      await expect(promise).rejects.toThrow(/placeholders are not supported in the args field/)
      expect(mockSpawn).not.toHaveBeenCalled()
    })

    it('rejects with ExecError when {{secret}} appears alongside static text in an arg', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo {{secret}}-{{secret}}'],
      }

      await expect(delegatedExec('x', request)).rejects.toThrow(ExecError)
    })

    it('rejects with ExecError when {{secret}} appears in any element of a multi-arg array', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo static', '{{secret}}'],
      }

      await expect(delegatedExec('val', request)).rejects.toThrow(ExecError)
    })

    it('rejects with ExecError when {{secret:name}} is used in args', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo {{secret:greeting}}'],
      }

      const promise = delegatedExec({ greeting: 'hello' }, request)

      await expect(promise).rejects.toThrow(ExecError)
      await expect(promise).rejects.toThrow(/placeholders are not supported in the args field/)
    })

    it('handles empty args array', async () => {
      const request: ExecRequest = {
        command: 'echo',
        args: [],
      }

      const result = await delegatedExec('s', request)

      expect(result.exitCode).toBe(0)
    })

    it('handles missing args', async () => {
      const request: ExecRequest = { command: 'echo' }

      const result = await delegatedExec('s', request)

      expect(result.exitCode).toBe(0)
    })
  })

  describe('env placeholder replacement', () => {
    // These assert on the raw injected value, so they opt out of the
    // default output redaction (issue #189) to observe the secret directly.
    it('replaces {{secret}} in env values', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo $MY_SECRET'],
        env: { MY_SECRET: '{{secret}}' },
        redact: false,
      }

      const result = await delegatedExec('envval', request)

      expect(result.stdout.trim()).toBe('envval')
      expect(result.exitCode).toBe(0)
    })

    it('merges injected env with process env', async () => {
      // PATH must be present for sh to work — env merge ensures it is
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo $INJECTED_VAR'],
        env: { INJECTED_VAR: '{{secret}}' },
        redact: false,
      }

      const result = await delegatedExec('merged', request)

      expect(result.stdout.trim()).toBe('merged')
    })

    it('handles missing env (no env injection)', async () => {
      const request: ExecRequest = {
        command: 'echo',
        args: ['no-env'],
      }

      const result = await delegatedExec('s', request)

      expect(result.stdout.trim()).toBe('no-env')
    })
  })

  describe('return value structure', () => {
    it('returns stdout, stderr, and exitCode', async () => {
      const request: ExecRequest = { command: 'echo', args: ['out'] }

      const result = await delegatedExec('s', request)

      expect(result).toHaveProperty('stdout')
      expect(result).toHaveProperty('stderr')
      expect(result).toHaveProperty('exitCode')
    })

    it('captures non-zero exit codes without throwing', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'exit 42'],
      }

      const result = await delegatedExec('s', request)

      expect(result.exitCode).toBe(42)
    })

    it('captures stderr output', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo errout >&2'],
      }

      const result = await delegatedExec('s', request)

      expect(result.stderr.trim()).toBe('errout')
    })
  })

  describe('cwd option', () => {
    it('executes the command in the specified working directory', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'pwd'],
        cwd: '/tmp',
      }

      const result = await delegatedExec('s', request)

      // /tmp may be a symlink (e.g. on macOS /tmp -> /private/tmp); resolve it.
      expect(result.stdout.trim()).toMatch(/tmp/)
      expect(result.exitCode).toBe(0)
    })
  })

  describe('named-secret mode (Record)', () => {
    it('replaces named secrets in env values', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo $API_KEY $DB_PASS'],
        env: {
          API_KEY: '{{secret:apiKey}}',
          DB_PASS: '{{secret:dbPass}}',
        },
        // Assert on the raw injected values — opt out of default redaction.
        redact: false,
      }

      const result = await delegatedExec({ apiKey: 'key123', dbPass: 'pass456' }, request)

      expect(result.stdout.trim()).toBe('key123 pass456')
    })
  })

  describe('output redaction (issue #189)', () => {
    // The security guarantee: a delegated command that echoes the injected
    // secret must NOT leak it back through ExecResult.stdout. By default the
    // captured output is scrubbed to [REDACTED].
    it('redacts the injected secret from stdout by default', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo "value is $S"'],
        env: { S: '{{secret}}' },
      }

      const result = await delegatedExec('sk_live_FAKE', request)

      expect(result.stdout).not.toContain('sk_live_FAKE')
      expect(result.stdout).toContain('[REDACTED]')
      expect(result.stdout.trim()).toBe('value is [REDACTED]')
    })

    it('redacts the injected secret from stderr by default', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo "leak $S" >&2'],
        env: { S: '{{secret}}' },
      }

      const result = await delegatedExec('sk_live_FAKE', request)

      expect(result.stderr).not.toContain('sk_live_FAKE')
      expect(result.stderr).toContain('[REDACTED]')
    })

    it('returns raw, unredacted output when redact is false', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo "value is $S"'],
        env: { S: '{{secret}}' },
        redact: false,
      }

      const result = await delegatedExec('sk_live_FAKE', request)

      expect(result.stdout.trim()).toBe('value is sk_live_FAKE')
      expect(result.stdout).not.toContain('[REDACTED]')
    })

    it('redacts all injected values in multi-secret (named) mode', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo "$API and $DB"'],
        env: { API: '{{secret:apiKey}}', DB: '{{secret:dbPass}}' },
      }

      const result = await delegatedExec({ apiKey: 'key-AAA', dbPass: 'pass-BBB' }, request)

      expect(result.stdout).not.toContain('key-AAA')
      expect(result.stdout).not.toContain('pass-BBB')
      expect(result.stdout.trim()).toBe('[REDACTED] and [REDACTED]')
    })

    it('redacts a secret value even when it appears in output but was not injected via that run', async () => {
      // A named secret present in the token map is scrubbed from output even if
      // the command surfaces it from another source — redaction is conservative.
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo "only $API"; echo "leaked pass-BBB"'],
        env: { API: '{{secret:apiKey}}' },
      }

      const result = await delegatedExec({ apiKey: 'key-AAA', dbPass: 'pass-BBB' }, request)

      expect(result.stdout).not.toContain('key-AAA')
      expect(result.stdout).not.toContain('pass-BBB')
    })
  })

  describe('negative cases', () => {
    it('rejects with ExecError when the command is not found', async () => {
      const request: ExecRequest = { command: 'nonexistent-command-xyz-123' }
      const promise = delegatedExec('s', request)

      await expect(promise).rejects.toThrow(ExecError)
      await expect(delegatedExec('s', request)).rejects.toThrow(
        /Command not found: nonexistent-command-xyz-123/,
      )
    })

    it('rejects with ExecError when {{secret}} is used in the command field', async () => {
      const request: ExecRequest = { command: '{{secret}}' }

      await expect(delegatedExec('s', request)).rejects.toThrow(ExecError)
      await expect(delegatedExec('s', request)).rejects.toThrow(
        /placeholders are not supported in the command field/,
      )
    })

    it('rejects with ExecError when {{secret:name}} is used in the command field', async () => {
      const request: ExecRequest = { command: '{{secret:apiKey}}' }

      await expect(delegatedExec({ apiKey: 'val' }, request)).rejects.toThrow(ExecError)
      await expect(delegatedExec({ apiKey: 'val' }, request)).rejects.toThrow(
        /placeholders are not supported in the command field/,
      )
    })

    it('rejects with ExecError when a named placeholder references an unknown secret', async () => {
      const request: ExecRequest = {
        command: 'echo',
        env: { MISSING: '{{secret:missing}}' },
      }

      await expect(delegatedExec({ apiKey: 'val' }, request)).rejects.toThrow(ExecError)
      await expect(delegatedExec({ apiKey: 'val' }, request)).rejects.toThrow(
        /Unknown secret name.*missing/,
      )
    })
  })
})

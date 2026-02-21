import { describe, it, expect } from 'vitest'
import { delegatedExec } from '../../../src/access/delegated-exec.js'
import type { ExecRequest } from '../../../src/access/types.js'

describe('delegatedExec', () => {
  describe('args placeholder replacement', () => {
    it('replaces {{secret}} in command args', async () => {
      const request: ExecRequest = {
        command: 'echo',
        args: ['{{secret}}'],
      }

      const result = await delegatedExec('hello', request)

      expect(result.stdout.trim()).toBe('hello')
      expect(result.exitCode).toBe(0)
    })

    it('replaces multiple occurrences in a single arg', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo {{secret}}-{{secret}}'],
      }

      const result = await delegatedExec('x', request)

      expect(result.stdout.trim()).toBe('x-x')
    })

    it('replaces placeholders in multiple args', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo {{secret}} static {{secret}}'],
      }

      const result = await delegatedExec('val', request)

      expect(result.stdout.trim()).toBe('val static val')
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
    it('replaces {{secret}} in env values', async () => {
      const request: ExecRequest = {
        command: 'sh',
        args: ['-c', 'echo $MY_SECRET'],
        env: { MY_SECRET: '{{secret}}' },
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

  describe('negative cases', () => {
    it('rejects when the command is not found', async () => {
      const request: ExecRequest = { command: 'nonexistent-command-xyz-123' }

      await expect(delegatedExec('s', request)).rejects.toThrow()
    })
  })
})

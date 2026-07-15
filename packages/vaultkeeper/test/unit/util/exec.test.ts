import { describe, it, expect, vi } from 'vitest'
import { execCommand, execCommandFull } from '../../../src/util/exec.js'
import { PluginNotFoundError, ExecError } from '../../../src/errors.js'

describe('execCommand', () => {
  it('returns trimmed stdout on success', async () => {
    const result = await execCommand('echo', ['  hello  '])
    // echo adds a newline; trim() removes surrounding whitespace
    expect(result).toBe('hello')
  })

  it('throws on non-zero exit code with stderr in message', async () => {
    await expect(execCommand('sh', ['-c', 'echo bad >&2; exit 1'])).rejects.toThrow(/bad/)
  })

  it('throws and includes the exit code in the message', async () => {
    await expect(execCommand('sh', ['-c', 'exit 2'])).rejects.toThrow(/2/)
  })

  // Regression: issue #127 — a non-zero exit code previously rejected with a
  // plain `Error`, breaking instanceof-based handling. It must now reject
  // with a typed ExecError naming the failed command.
  it('rejects with a typed ExecError naming the command', async () => {
    try {
      await execCommand('sh', ['-c', 'exit 2'])
      expect.unreachable('execCommand should have rejected for a non-zero exit code')
    } catch (err) {
      if (!(err instanceof ExecError)) {
        throw err
      }
      expect(err.command).toBe('sh')
    }
  })
})

describe('execCommandFull', () => {
  it('returns full result with stdout, stderr, and exitCode on success', async () => {
    const result = await execCommandFull('echo', ['hello'])
    expect(result.stdout.trim()).toBe('hello')
    expect(result.stderr).toBe('')
    expect(result.exitCode).toBe(0)
  })

  it('returns non-zero exitCode without throwing', async () => {
    const result = await execCommandFull('sh', ['-c', 'exit 42'])
    expect(result.exitCode).toBe(42)
  })

  it('captures stderr output', async () => {
    const result = await execCommandFull('sh', ['-c', 'echo errout >&2'])
    expect(result.stderr.trim()).toBe('errout')
    expect(result.exitCode).toBe(0)
  })

  it('kills the process and rejects after timeout', async () => {
    await expect(execCommandFull('sleep', ['10'], { timeoutMs: 50 })).rejects.toThrow(/timed out/)
  }, 5000)

  // Regression: issue #127 — a timeout previously rejected with a plain
  // `Error`, breaking instanceof-based handling. It must now reject with a
  // typed ExecError naming the command.
  it('rejects with a typed ExecError naming the command on timeout', async () => {
    try {
      await execCommandFull('sleep', ['10'], { timeoutMs: 50 })
      expect.unreachable('execCommandFull should have rejected after the timeout')
    } catch (err) {
      if (!(err instanceof ExecError)) {
        throw err
      }
      expect(err.command).toBe('sleep')
    }
  }, 5000)

  it('pipes stdin to the process', async () => {
    const result = await execCommandFull('cat', [], { stdin: 'from-stdin' })
    expect(result.stdout).toBe('from-stdin')
    expect(result.exitCode).toBe(0)
  })

  it('wraps ENOENT spawn error in PluginNotFoundError', async () => {
    await expect(
      execCommandFull('this-binary-absolutely-does-not-exist-anywhere', ['--version']),
    ).rejects.toThrow(PluginNotFoundError)
  })

  // Regression: PR #164 review (issue #127) — the timeout timer was never
  // cleared when the process closed before it fired. Left pending, it kept
  // the event loop alive until it eventually fired and called proc.kill() on
  // an already-exited process.
  //
  // Wraps the real setTimeout (rather than asserting a call count on the
  // clearTimeout spy) so the assertion pins the *specific* handle our
  // setTimeout call returned — immune to unrelated clearTimeout calls
  // elsewhere in the process, unlike a global call-count assertion (review
  // feedback on the first version of this test). A distinctive timeoutMs
  // value (98765, far from any other timeoutMs used in this file) identifies
  // our setTimeout call among any others that may fire during the test.
  it('clears the timeout timer once the process closes, before it fires', async () => {
    const realSetTimeout = globalThis.setTimeout
    let ourTimeoutHandle: NodeJS.Timeout | undefined
    const setTimeoutSpy = vi
      .spyOn(globalThis, 'setTimeout')
      .mockImplementation((callback: () => void, ms?: number) => {
        const handle = realSetTimeout(callback, ms)
        if (ms === 98_765) {
          ourTimeoutHandle = handle
        }
        return handle
      })
    const clearTimeoutSpy = vi.spyOn(globalThis, 'clearTimeout')

    const result = await execCommandFull('echo', ['hello'], { timeoutMs: 98_765 })
    expect(result.exitCode).toBe(0)

    expect(ourTimeoutHandle).toBeDefined()
    expect(clearTimeoutSpy).toHaveBeenCalledWith(ourTimeoutHandle)

    setTimeoutSpy.mockRestore()
    clearTimeoutSpy.mockRestore()
  })

  // Same regression, via the error path (spawn ENOENT) rather than 'close'.
  it('clears the timeout timer when spawn errors, before it fires', async () => {
    const realSetTimeout = globalThis.setTimeout
    let ourTimeoutHandle: NodeJS.Timeout | undefined
    const setTimeoutSpy = vi
      .spyOn(globalThis, 'setTimeout')
      .mockImplementation((callback: () => void, ms?: number) => {
        const handle = realSetTimeout(callback, ms)
        if (ms === 98_766) {
          ourTimeoutHandle = handle
        }
        return handle
      })
    const clearTimeoutSpy = vi.spyOn(globalThis, 'clearTimeout')

    await expect(
      execCommandFull('this-binary-absolutely-does-not-exist-anywhere', ['--version'], {
        timeoutMs: 98_766,
      }),
    ).rejects.toThrow(PluginNotFoundError)

    expect(ourTimeoutHandle).toBeDefined()
    expect(clearTimeoutSpy).toHaveBeenCalledWith(ourTimeoutHandle)

    setTimeoutSpy.mockRestore()
    clearTimeoutSpy.mockRestore()
  })
})

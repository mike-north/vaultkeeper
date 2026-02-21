import { describe, it, expect } from 'vitest'
import { execCommand, execCommandFull } from '../../../src/util/exec.js'

describe('execCommand', () => {
  it('returns trimmed stdout on success', async () => {
    const result = await execCommand('echo', ['  hello  '])
    // echo adds a newline; trim() removes surrounding whitespace
    expect(result).toBe('hello')
  })

  it('throws on non-zero exit code with stderr in message', async () => {
    await expect(
      execCommand('sh', ['-c', 'echo bad >&2; exit 1']),
    ).rejects.toThrow(/bad/)
  })

  it('throws and includes the exit code in the message', async () => {
    await expect(
      execCommand('sh', ['-c', 'exit 2']),
    ).rejects.toThrow(/2/)
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
    await expect(
      execCommandFull('sleep', ['10'], { timeoutMs: 50 }),
    ).rejects.toThrow(/timed out/)
  }, 5000)

  it('pipes stdin to the process', async () => {
    const result = await execCommandFull('cat', [], { stdin: 'from-stdin' })
    expect(result.stdout).toBe('from-stdin')
    expect(result.exitCode).toBe(0)
  })
})

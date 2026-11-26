import { describe, it, expect, vi } from 'vitest'
import { Buffer } from 'node:buffer'
import { StringDecoder } from 'node:string_decoder'
import * as fs from 'node:fs/promises'
import { writeFileSync } from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
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
  it('wipes stdout chunks while preserving split UTF-8 characters', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-exec-utf8-'))
    const signal = path.join(dir, 'continue')
    const chunks: Buffer[] = []
    const original: unknown = Reflect.get(StringDecoder.prototype, 'write')
    if (typeof original !== 'function') throw new TypeError('Missing decoder')
    const spy = vi.spyOn(StringDecoder.prototype, 'write').mockImplementation(function (
      this: StringDecoder,
      data,
    ) {
      if (Buffer.isBuffer(data)) {
        chunks.push(data)
        if (data.length === 1 && data[0] === 0xe2) writeFileSync(signal, '')
      }
      const decoded: unknown = Reflect.apply(original, this, [data])
      if (typeof decoded !== 'string') throw new TypeError('Invalid decoded output')
      return decoded
    })
    try {
      const result = await execCommandFull(
        process.execPath,
        [
          '-e',
          "const fs = require('fs'); process.stdout.write(Buffer.from([0xe2])); const timer = setInterval(() => { if (fs.existsSync(process.argv[1])) { clearInterval(timer); process.stdout.write(Buffer.from([0x82, 0xac])); } }, 10)",
          signal,
        ],
        { timeoutMs: 5000 },
      )
      expect(result.stdout).toBe('€')
      expect(chunks.length).toBeGreaterThanOrEqual(2)
      expect(chunks.every((chunk) => chunk.every((byte) => byte === 0))).toBe(true)
    } finally {
      spy.mockRestore()
      await fs.rm(dir, { recursive: true, force: true })
    }
  })
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

  it('wipes stderr chunks after decoding potentially sensitive output', async () => {
    const original: unknown = Reflect.get(StringDecoder.prototype, 'write')
    if (typeof original !== 'function') throw new TypeError('Missing decoder')
    const chunks: Buffer[] = []
    const spy = vi.spyOn(StringDecoder.prototype, 'write').mockImplementation(function (
      this: StringDecoder,
      data,
    ) {
      const decoded: unknown = Reflect.apply(original, this, [data])
      if (typeof decoded !== 'string') throw new TypeError('Invalid decoded output')
      if (decoded.includes('unique-sensitive-stderr-marker') && Buffer.isBuffer(data))
        chunks.push(data)
      return decoded
    })
    try {
      const result = await execCommandFull('sh', [
        '-c',
        'printf unique-sensitive-stderr-marker >&2',
      ])
      expect(result.stderr).toBe('unique-sensitive-stderr-marker')
      expect(chunks.length).toBeGreaterThan(0)
      expect(chunks.every((chunk) => chunk.every((byte) => byte === 0))).toBe(true)
    } finally {
      spy.mockRestore()
    }
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

  it('reports an interrupted stdin write even if the child exits zero', async () => {
    await expect(
      execCommandFull(process.execPath, ['-e', 'process.exit(0)'], {
        stdin: 'x'.repeat(1024 * 1024),
      }),
    ).rejects.toThrow(ExecError)
  })

  it('wraps ENOENT spawn error in PluginNotFoundError', async () => {
    await expect(
      execCommandFull('this-binary-absolutely-does-not-exist-anywhere', ['--version']),
    ).rejects.toThrow(PluginNotFoundError)
  })

  // Regression (review thread 3591242590): non-ENOENT spawn failures (EACCES
  // on the target, EMFILE, ...) previously rejected with the raw Node error —
  // the last plain-error escape on this utility's failure paths. Spawning a
  // non-executable file yields EACCES deterministically on POSIX.
  it.skipIf(process.platform === 'win32')(
    'wraps a non-ENOENT spawn failure (EACCES) in a typed ExecError',
    async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vk-exec-eacces-'))
      const target = path.join(dir, 'not-executable.sh')
      try {
        await fs.writeFile(target, '#!/bin/sh\necho hi\n', { mode: 0o644 })

        const caught = await execCommandFull(target, []).then(
          () => undefined,
          (err: unknown) => err,
        )
        expect(caught).toBeInstanceOf(ExecError)
        if (caught instanceof ExecError) {
          expect(caught.command).toBe(target)
        }
      } finally {
        await fs.rm(dir, { recursive: true, force: true })
      }
    },
  )

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

    // try/finally so a failing assertion (or a rejecting execCommandFull)
    // can't leak the global setTimeout/clearTimeout spies into later tests.
    try {
      const result = await execCommandFull('echo', ['hello'], { timeoutMs: 98_765 })
      expect(result.exitCode).toBe(0)

      expect(ourTimeoutHandle).toBeDefined()
      expect(clearTimeoutSpy).toHaveBeenCalledWith(ourTimeoutHandle)
    } finally {
      setTimeoutSpy.mockRestore()
      clearTimeoutSpy.mockRestore()
    }
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

    // try/finally: same spy-leak guard as the close-path test above.
    try {
      await expect(
        execCommandFull('this-binary-absolutely-does-not-exist-anywhere', ['--version'], {
          timeoutMs: 98_766,
        }),
      ).rejects.toThrow(PluginNotFoundError)

      expect(ourTimeoutHandle).toBeDefined()
      expect(clearTimeoutSpy).toHaveBeenCalledWith(ourTimeoutHandle)
    } finally {
      setTimeoutSpy.mockRestore()
      clearTimeoutSpy.mockRestore()
    }
  })
})

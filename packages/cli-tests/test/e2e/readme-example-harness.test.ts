/**
 * Guards the on-disk isolation of README code examples from workspace lint.
 */
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import * as path from 'node:path'

import { beforeEach, describe, expect, it, vi } from 'vitest'

import { runCodeFence, typecheckCodeFence } from './readme-example-harness.js'
import type { Fence } from './readme-example-harness.js'

vi.mock('node:child_process', () => ({ spawnSync: vi.fn() }))

/** One standalone fence can exercise the placement in either mode. */
const fence: Fence = {
  readme: 'README.md',
  lang: 'ts',
  code: 'export {}',
  startLine: 1,
  skipped: false,
  skipReason: undefined,
  run: true,
  runReason: undefined,
}

describe('README code fence scratch files', () => {
  beforeEach(() => {
    vi.mocked(spawnSync).mockReset()
    vi.mocked(spawnSync).mockReturnValue({
      pid: 1,
      output: [null, '', ''],
      stdout: '',
      stderr: '',
      status: 0,
      signal: null,
    })
  })

  it.each([
    { mode: 'type-checking', run: typecheckCodeFence, file: 'tsconfig.json' },
    { mode: 'execution', run: runCodeFence, file: 'snippet.ts' },
  ])('uses an OS temp project for $mode', ({ run, file }) => {
    expect(run(fence).exitCode).toBe(0)

    // The recorded arguments show where the files existed while the child ran,
    // even though the harness has already cleaned up the project.
    const command = vi.mocked(spawnSync).mock.calls[0]
    const entry = command?.[1]?.find((arg) => path.basename(arg) === file) ?? ''
    expect(path.dirname(path.dirname(entry))).toBe(path.resolve(tmpdir()))
  })
})

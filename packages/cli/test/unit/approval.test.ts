import { describe, it, expect, vi, afterEach } from 'vitest'
import type { ApprovalInfo } from '../../src/types.js'

describe('promptApproval', () => {
  const originalIsTTY = process.stdin.isTTY

  afterEach(() => {
    Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, writable: true })
    vi.restoreAllMocks()
  })

  it('should throw when stdin is not a TTY', async () => {
    Object.defineProperty(process.stdin, 'isTTY', { value: false, writable: true })
    const { promptApproval } = await import('../../src/approval.js')
    const info: ApprovalInfo = {
      caller: './test.sh',
      trustInfo: 'Unknown',
      secret: 'my-key',
    }
    await expect(promptApproval(info)).rejects.toThrow('interactive approval')
  })
})

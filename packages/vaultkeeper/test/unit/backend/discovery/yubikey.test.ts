/**
 * Tests for YubiKey backend discovery.
 *
 * @see https://developers.yubico.com/yubikey-manager/
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../../../src/util/exec.js', () => ({
  execCommand: vi.fn(),
  execCommandFull: vi.fn(),
}))

import { execCommand } from '../../../../src/util/exec.js'
import {
  listDevices,
  isSlotConfigured,
  createYubikeySetup,
} from '../../../../src/backend/discovery/yubikey.js'
import { SetupError } from '../../../../src/errors.js'

const mockExecCommand = vi.mocked(execCommand)

/** Drive a setup generator to completion, answering each question in sequence. */
async function runSetup(
  answers: string[],
): Promise<{ questions: string[]; result: { options: Record<string, string> } }> {
  const gen = createYubikeySetup()
  const questions: string[] = []
  let answerIndex = 0

  let next = await gen.next()
  while (!next.done) {
    const question = next.value
    questions.push(question.prompt)
    const answer = answers[answerIndex++] ?? ''
    next = await gen.next(answer)
  }

  return { questions, result: next.value }
}

describe('listDevices', () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })

  it('should parse serial list and info output into SetupChoice[]', async () => {
    mockExecCommand
      .mockResolvedValueOnce('12345678\n87654321')
      .mockResolvedValueOnce(
        'Device type: YubiKey 5 NFC\nSerial number: 12345678\nFirmware version: 5.4.3',
      )
      .mockResolvedValueOnce(
        'Device type: YubiKey 5C\nSerial number: 87654321\nFirmware version: 5.2.7',
      )

    const result = await listDevices()

    expect(result).toHaveLength(2)
    expect(result[0]).toEqual({ value: '12345678', label: 'YubiKey 5 NFC (serial: 12345678)' })
    expect(result[1]).toEqual({ value: '87654321', label: 'YubiKey 5C (serial: 87654321)' })
  })

  it('should handle a single device', async () => {
    mockExecCommand
      .mockResolvedValueOnce('12345678')
      .mockResolvedValueOnce(
        'Device type: YubiKey 5 NFC\nSerial number: 12345678\nFirmware version: 5.4.3',
      )

    const result = await listDevices()

    expect(result).toHaveLength(1)
    expect(result[0]).toEqual({ value: '12345678', label: 'YubiKey 5 NFC (serial: 12345678)' })
  })

  it('should return an empty array when ykman reports no devices', async () => {
    mockExecCommand.mockResolvedValueOnce('')

    const result = await listDevices()

    expect(result).toHaveLength(0)
  })

  it('should propagate errors when ykman is not found', async () => {
    mockExecCommand.mockRejectedValueOnce(new Error('command not found: ykman'))

    await expect(listDevices()).rejects.toThrow('command not found: ykman')
  })

  it('should fall back to "YubiKey" label when Device type line is absent', async () => {
    mockExecCommand
      .mockResolvedValueOnce('12345678')
      .mockResolvedValueOnce('Serial number: 12345678\nFirmware version: 5.4.3')

    const result = await listDevices()

    expect(result[0]).toEqual({ value: '12345678', label: 'YubiKey (serial: 12345678)' })
  })
})

describe('isSlotConfigured', () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })

  it('should return true when the slot line contains "programmed"', async () => {
    mockExecCommand.mockResolvedValueOnce('Slot 1: programmed\nSlot 2: programmed')

    const result = await isSlotConfigured('12345678', 2)

    expect(result).toBe(true)
  })

  it('should return false when the slot line contains "empty"', async () => {
    mockExecCommand.mockResolvedValueOnce('Slot 1: programmed\nSlot 2: empty')

    const result = await isSlotConfigured('12345678', 2)

    expect(result).toBe(false)
  })

  it('should return false when the slot line is absent entirely', async () => {
    mockExecCommand.mockResolvedValueOnce('Slot 1: programmed')

    const result = await isSlotConfigured('12345678', 2)

    expect(result).toBe(false)
  })

  it('should return false when the output is empty', async () => {
    mockExecCommand.mockResolvedValueOnce('')

    const result = await isSlotConfigured('12345678', 2)

    expect(result).toBe(false)
  })

  it('should propagate errors when ykman is not found', async () => {
    mockExecCommand.mockRejectedValueOnce(new Error('command not found: ykman'))

    await expect(isSlotConfigured('12345678', 2)).rejects.toThrow('command not found: ykman')
  })
})

describe('createYubikeySetup', () => {
  beforeEach(() => {
    // resetAllMocks clears the mockResolvedValueOnce queue in addition to call history,
    // preventing unconsumed mock responses from bleeding across tests.
    vi.resetAllMocks()
  })

  it('should auto-select single device and return options when slot 2 is configured', async () => {
    // listDevices: ykman list --serials
    mockExecCommand
      .mockResolvedValueOnce('12345678')
      .mockResolvedValueOnce(
        'Device type: YubiKey 5 NFC\nSerial number: 12345678\nFirmware version: 5.4.3',
      )
      // isSlotConfigured: ykman --device 12345678 otp info
      .mockResolvedValueOnce('Slot 1: programmed\nSlot 2: programmed')

    const { questions, result } = await runSetup([])

    expect(questions).toHaveLength(0)
    expect(result.options).toEqual({ serial: '12345678' })
  })

  it('should yield a device selection question when multiple devices are present', async () => {
    // listDevices: serial list + two info calls
    mockExecCommand
      .mockResolvedValueOnce('12345678\n87654321')
      .mockResolvedValueOnce(
        'Device type: YubiKey 5 NFC\nSerial number: 12345678\nFirmware version: 5.4.3',
      )
      .mockResolvedValueOnce(
        'Device type: YubiKey 5C\nSerial number: 87654321\nFirmware version: 5.2.7',
      )
      // isSlotConfigured for selected device
      .mockResolvedValueOnce('Slot 1: programmed\nSlot 2: programmed')

    const { questions, result } = await runSetup(['12345678'])

    expect(questions).toHaveLength(1)
    expect(questions[0]).toBe('Select a YubiKey device')
    expect(result.options).toEqual({ serial: '12345678' })
  })

  it('should include device choices in the yielded question', async () => {
    mockExecCommand
      .mockResolvedValueOnce('12345678\n87654321')
      .mockResolvedValueOnce(
        'Device type: YubiKey 5 NFC\nSerial number: 12345678\nFirmware version: 5.4.3',
      )
      .mockResolvedValueOnce(
        'Device type: YubiKey 5C\nSerial number: 87654321\nFirmware version: 5.2.7',
      )
      .mockResolvedValueOnce('Slot 1: programmed\nSlot 2: programmed')

    const gen = createYubikeySetup()
    const first = await gen.next()

    expect(first.done).toBe(false)
    if (!first.done) {
      expect(first.value.key).toBe('serial')
      expect(first.value.choices).toHaveLength(2)
      expect(first.value.choices?.[0]).toEqual({
        value: '12345678',
        label: 'YubiKey 5 NFC (serial: 12345678)',
      })
    }
  })

  it('should throw SetupError when slot 2 is not configured', async () => {
    mockExecCommand
      .mockResolvedValueOnce('12345678')
      .mockResolvedValueOnce(
        'Device type: YubiKey 5 NFC\nSerial number: 12345678\nFirmware version: 5.4.3',
      )
      // slot 2 empty
      .mockResolvedValueOnce('Slot 1: programmed\nSlot 2: empty')

    const gen = createYubikeySetup()
    await expect(gen.next()).rejects.toBeInstanceOf(SetupError)
  })

  it('should include instructions for configuring slot 2 in the SetupError', async () => {
    mockExecCommand
      .mockResolvedValueOnce('12345678')
      .mockResolvedValueOnce(
        'Device type: YubiKey 5 NFC\nSerial number: 12345678\nFirmware version: 5.4.3',
      )
      .mockResolvedValueOnce('Slot 1: programmed\nSlot 2: empty')

    const gen = createYubikeySetup()
    const error = await gen.next().catch((e: unknown) => e)

    expect(error).toBeInstanceOf(SetupError)
    if (error instanceof SetupError) {
      expect(error.message).toContain('slot 2')
      expect(error.message).toContain('ykman otp chalresp')
      expect(error.dependency).toBe('ykman')
    }
  })

  it('should throw SetupError immediately when no devices are connected', async () => {
    mockExecCommand.mockResolvedValueOnce('')

    const gen = createYubikeySetup()
    await expect(gen.next()).rejects.toBeInstanceOf(SetupError)
  })

  it('should include a helpful message in the no-devices SetupError', async () => {
    mockExecCommand.mockResolvedValueOnce('')

    const gen = createYubikeySetup()
    const error = await gen.next().catch((e: unknown) => e)

    expect(error).toBeInstanceOf(SetupError)
    if (error instanceof SetupError) {
      expect(error.message).toContain('No YubiKey devices found')
      expect(error.dependency).toBe('ykman')
    }
  })
})

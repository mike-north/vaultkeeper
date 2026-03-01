/**
 * Interactive setup discovery for the YubiKey backend.
 *
 * @internal
 */

import { execCommand } from '../../util/exec.js'
import { SetupError } from '../../errors.js'
import type { SetupChoice, SetupQuestion, SetupResult } from '../setup-types.js'

/**
 * Retrieve all connected YubiKey serials and build a display list.
 * @internal
 */
export async function listDevices(): Promise<SetupChoice[]> {
  const rawSerials = await execCommand('ykman', ['list', '--serials'])
  if (rawSerials.trim() === '') {
    return []
  }

  const serials = rawSerials
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)

  const choices: SetupChoice[] = []

  for (const serial of serials) {
    const info = await execCommand('ykman', ['--device', serial, 'info'])
    // Extract the device type from the first line: "Device type: YubiKey 5 NFC"
    const deviceTypeLine = info.split('\n').find((line) => line.startsWith('Device type:'))
    const deviceType =
      deviceTypeLine !== undefined ? deviceTypeLine.replace('Device type:', '').trim() : 'YubiKey'

    choices.push({
      value: serial,
      label: `${deviceType} (serial: ${serial})`,
    })
  }

  return choices
}

/**
 * Check whether the specified OTP slot is configured on a given YubiKey.
 * @internal
 */
export async function isSlotConfigured(serial: string, slot: number): Promise<boolean> {
  const info = await execCommand('ykman', ['--device', serial, 'otp', 'info'])
  const slotLine = info.split('\n').find((line) => line.startsWith(`Slot ${String(slot)}:`))
  if (slotLine === undefined) {
    return false
  }
  return slotLine.includes('programmed')
}

/**
 * Async generator that walks the user through selecting and validating a
 * YubiKey for use as a backend.
 *
 * Yields {@link SetupQuestion} prompts and returns a {@link SetupResult}
 * containing the selected serial number.
 *
 * @throws {@link SetupError} when no devices are connected or slot 2 is not
 *   configured.
 * @internal
 */
export async function* createYubikeySetup(): AsyncGenerator<SetupQuestion, SetupResult, string> {
  const choices = await listDevices()

  if (choices.length === 0) {
    throw new SetupError(
      'No YubiKey devices found. Connect a YubiKey and try again.',
      'ykman',
    )
  }

  let selectedSerial: string

  if (choices.length === 1) {
    // Array#at(0) returns T | undefined. The undefined guard is unreachable at
    // runtime (length === 1 guarantees an element) but satisfies the type system.
    const first = choices.at(0)
    if (first === undefined) {
      throw new SetupError('Unexpected empty device list.', 'ykman')
    }
    selectedSerial = first.value
  } else {
    const answer = yield {
      key: 'serial',
      prompt: 'Select a YubiKey device',
      choices,
    } satisfies SetupQuestion

    selectedSerial = answer
  }

  const slotConfigured = await isSlotConfigured(selectedSerial, 2)
  if (!slotConfigured) {
    throw new SetupError(
      `YubiKey (serial: ${selectedSerial}) slot 2 is not configured. ` +
        'Configure it with: ykman otp chalresp --generate 2',
      'ykman',
    )
  }

  return {
    options: { serial: selectedSerial },
  } satisfies SetupResult
}

import { parseArgs } from 'node:util'
import * as path from 'node:path'
import { VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

export async function devModeCommand(args: string[]): Promise<number> {
  const { positionals, values } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      script: { type: 'string' },
    },
    strict: true,
  })

  const action = positionals[0]

  if ((action !== 'enable' && action !== 'disable') || values.script === undefined) {
    process.stderr.write('Usage: vaultkeeper dev-mode <enable|disable> --script <path>\n')
    return 1
  }

  const scriptPath = path.resolve(values.script)
  const enabled = action === 'enable'

  try {
    const vault = await VaultKeeper.init()
    await vault.setDevelopmentMode(scriptPath, enabled)
    process.stdout.write(
      `Development mode ${enabled ? 'enabled' : 'disabled'} for ${scriptPath}\n`,
    )
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}

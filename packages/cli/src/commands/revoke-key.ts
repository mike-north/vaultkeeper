import { VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

export async function revokeKeyCommand(_args: string[]): Promise<number> {
  try {
    const vault = await VaultKeeper.init()
    await vault.revokeKey()
    process.stdout.write('Key revoked successfully.\n')
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}

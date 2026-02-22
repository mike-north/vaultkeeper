import { VaultKeeper } from 'vaultkeeper'
import { formatError } from '../output.js'

export async function rotateKeyCommand(_args: string[]): Promise<number> {
  try {
    const vault = await VaultKeeper.init()
    await vault.rotateKey()
    process.stdout.write('Key rotated successfully.\n')
    return 0
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`)
    return 1
  }
}

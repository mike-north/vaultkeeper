// Exercise first use and reopen in a separate process so umask is isolated.
import { VaultKeeper } from '../dist/index.js'
import { stat } from 'node:fs/promises'
import { join } from 'node:path'
import { strict as assert } from 'node:assert'

const dir = process.argv[2]
process.umask(0o400)
const first = await VaultKeeper.init({ configDir: dir, skipDoctor: true })
await first.store('example', 'value')
for (const file of ['.keys.wrap', 'keys.enc', 'file/.key']) {
  assert.equal((await stat(join(dir, file))).mode & 0o777, 0o600)
}
await VaultKeeper.init({ configDir: dir, skipDoctor: true })

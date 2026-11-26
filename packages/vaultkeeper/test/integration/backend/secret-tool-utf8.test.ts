import { describe, expect, it, vi } from 'vitest'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { SecretToolBackend } from '../../../src/backend/secret-tool-backend.js'
import { splitUtf8Script, splitUtf8Text } from '../../helpers/split-utf8-fixture.js'

describe.skipIf(process.platform === 'win32')('SecretToolBackend UTF-8 output', () => {
  it('preserves a credential split across subprocess chunks', async () => {
    const fixtureDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vaultkeeper-secret-tool-'))
    try {
      await fs.writeFile(
        path.join(fixtureDir, 'secret-tool'),
        `#!/usr/bin/env node\n${splitUtf8Script()}`,
        { mode: 0o755 },
      )
      vi.stubEnv('PATH', `${fixtureDir}${path.delimiter}${process.env.PATH ?? ''}`)

      const backend = new SecretToolBackend()
      await expect(backend.retrieve('split-secret')).resolves.toBe(splitUtf8Text.slice(0, -1))
    } finally {
      vi.unstubAllEnvs()
      await fs.rm(fixtureDir, { recursive: true, force: true })
    }
  })
})

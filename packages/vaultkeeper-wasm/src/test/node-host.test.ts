/* eslint-disable @typescript-eslint/no-floating-promises -- node:test owns returned promises */

import * as assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createNodeHost } from '../node-host.js'

const unixOnly = { skip: process.platform === 'win32' }

async function withStorage(run: (directory: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), 'vaultkeeper-node-host-'))
  try {
    await chmod(directory, 0o755)
    await run(directory)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

test('legacy descriptors see only old bytes and symlinks are rejected', unixOnly, async () => {
  await withStorage(async (directory) => {
    const host = createNodeHost(directory)
    const target = join(directory, 'key')
    const link = join(directory, 'link')
    await writeFile(target, 'old')
    await chmod(target, 0o666)
    await symlink(target, link)
    const previous = await open(target, 'r')
    try {
      await assert.rejects(host.writeFile(link, Buffer.from('unexpected'), 0o600), {
        name: 'HostFilesystemError',
        path: link,
      })
      assert.equal((await stat(target)).mode & 0o777, 0o666)
      await host.writeFile(target, Buffer.from('replacement'), 0o600)
      assert.equal(await readFile(target, 'utf8'), 'replacement')
      assert.equal((await stat(target)).mode & 0o777, 0o600)
      assert.equal(await previous.readFile('utf8'), 'old')
    } finally {
      await previous.close()
    }
  })
})

test('concurrent writes publish complete and private files', unixOnly, async () => {
  await withStorage(async (directory) => {
    const host = createNodeHost(directory)
    const target = join(directory, 'key')
    const payloads = [Buffer.alloc(64 * 1024, 1), Buffer.alloc(128 * 1024, 2)]
    await Promise.all(payloads.map((payload) => host.writeFile(target, payload, 0o600)))
    const actual = await readFile(target)
    assert.ok(payloads.some((payload) => payload.equals(actual)))
    assert.equal((await stat(target)).mode & 0o777, 0o600)
    assert.deepEqual(await readdir(directory), ['key'])
  })
})

test('failed or interrupted key writes leave the destination intact', unixOnly, async () => {
  const script = `
    import * as assert from 'node:assert/strict'
    import { open } from 'node:fs/promises'
    import { createNodeHost } from ${JSON.stringify(new URL('../node-host.js', import.meta.url))}

    const [directory, scenario] = process.argv.slice(1)
    const host = createNodeHost(directory)
    const existing = directory + '/existing-key'
    await host.writeFile(existing, Buffer.from('old fixture'), 0o600)
    const sample = await open(existing, 'r')
    const fileHandle = Object.getPrototypeOf(sample)
    await sample.close()
    if (scenario === 'interrupt') {
      // Stop just after writing one byte, before rename or cleanup.
      fileHandle.writeFile = async function (bytes) {
        await this.write(bytes.subarray(0, 1))
        process.kill(process.pid, 'SIGKILL')
      }
    }
    if (scenario === 'chmod') {
      fileHandle.chmod = async function () {
        throw Object.assign(new Error('permission denied'), { code: 'EPERM' })
      }
      fileHandle.writeFile = async function () {
        process.exit(2)
      }
    }
    for (const path of [directory + '/missing-key', existing]) {
      await assert.rejects(host.writeFile(path, new Uint8Array(16 * 1024).fill(1), 0o600), {
        name: 'HostFilesystemError', code: scenario === 'chmod' ? 'EPERM' : 'EFBIG', path,
      })
    }
  `
  for (const scenario of ['partial', 'interrupt', 'chmod']) {
    await withStorage(async (directory) => {
      const physical = join(directory, 'storage')
      const nested = join(physical, 'nested')
      const alias = join(directory, 'alias')
      await mkdir(nested, { recursive: true, mode: 0o755 })
      await symlink(nested, alias)
      const child = spawnSync(
        '/bin/sh',
        [
          '-c',
          `umask 000; ulimit -f 1 || exit; trap '' XFSZ; exec "$@"`,
          'vaultkeeper-test',
          process.execPath,
          '--input-type=module',
          '--eval',
          script,
          `${alias}/..`,
          scenario,
        ],
        { encoding: 'utf8' },
      )
      assert.ifError(child.error)
      if (scenario === 'interrupt') {
        assert.equal(child.signal, 'SIGKILL', child.stderr)
      } else {
        assert.equal(child.status, 0, child.stderr)
      }
      assert.deepEqual((await readdir(directory)).sort(), ['alias', 'storage'])
      await assert.rejects(stat(join(physical, 'missing-key')), { code: 'ENOENT' })
      const existing = join(physical, 'existing-key')
      assert.equal((await stat(existing)).mode & 0o777, 0o600)
      assert.equal(await readFile(existing, 'utf8'), 'old fixture')
      const staging = (await readdir(physical)).filter((entry) =>
        entry.startsWith('.vaultkeeper-write-'),
      )
      assert.equal(staging.length, scenario === 'interrupt' ? 1 : 0)
      for (const entry of staging) {
        const metadata = await stat(join(physical, entry))
        assert.equal(metadata.size, 1)
        assert.equal(metadata.mode & 0o777, 0o600)
      }
    })
  }
})

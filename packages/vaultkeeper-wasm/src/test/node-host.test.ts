import * as assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
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

await test(
  'legacy descriptors see only old bytes and symlinks are rejected',
  unixOnly,
  async () => {
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
  },
)

await test('concurrent writes publish complete and private files', unixOnly, async () => {
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

/** Inspect the ACL separately from the mode bits printed on the first line. */
function aclListing(path: string): string {
  return execFileSync('/bin/ls', ['-led', path], { encoding: 'utf8' })
}

/** Prove the fixture has an effective read grant despite an owner-only mode. */
async function grantInheritedRead(directory: string): Promise<void> {
  await chmod(directory, 0o755)
  execFileSync('/bin/chmod', [
    '+a',
    'everyone allow read,file_inherit,directory_inherit',
    directory,
  ])
  const probe = join(directory, 'acl-probe')
  await writeFile(probe, '', { mode: 0o600 })
  assert.match(aclListing(probe), /everyone inherited allow read/u)
  await rm(probe)
}

await test(
  'published keys exclude inherited read ACLs',
  { skip: process.platform !== 'darwin' },
  async () => {
    await withStorage(async (directory) => {
      await grantInheritedRead(directory)
      const parentAcl = aclListing(directory).split('\n').slice(1)
      const host = createNodeHost(directory)
      const target = join(directory, 'key')
      const fixture = Buffer.alloc(32, 1)
      await host.writeFile(target, fixture, 0o600)
      assert.deepEqual(await readFile(target), fixture)
      assert.equal((await stat(target)).mode & 0o777, 0o600)
      assert.doesNotMatch(aclListing(target), /\n\s*\d+:/u)
      assert.deepEqual(aclListing(directory).split('\n').slice(1), parentAcl)
      assert.equal((await stat(directory)).mode & 0o777, 0o755)
      assert.deepEqual(await readdir(directory), ['key'])
    })
  },
)

/** Run a fresh file-backed vault with only the grants needed by the SDK and storage. */
function storeWithNodePermissions(directory: string, allowChild: boolean, umask: number) {
  const script = `
    import * as assert from 'node:assert/strict'
    import { randomUUID } from 'node:crypto'
    import { VaultKeeper } from ${JSON.stringify(new URL('../index.js', import.meta.url))}

    assert.equal(process.permission.has('child'), ${String(allowChild)})
    process.umask(${String(umask)})
    const vault = await VaultKeeper.create({ skipDoctor: true }, process.argv[1])
    try {
      const value = randomUUID()
      await vault.store('permission-test', value)
      assert.equal(await vault.retrieve('permission-test'), value)
    } finally {
      vault.dispose()
    }
  `
  return spawnSync(
    process.execPath,
    [
      '--permission',
      '--preserve-symlinks',
      `--allow-fs-read=${fileURLToPath(new URL('../../', import.meta.url))}`,
      `--allow-fs-read=${directory}`,
      `--allow-fs-write=${directory}`,
      ...(allowChild ? ['--allow-child-process'] : []),
      '--input-type=module',
      '--eval',
      script,
      directory,
    ],
    { encoding: 'utf8', env: { ...process.env, NODE_OPTIONS: '' } },
  )
}

/** The stable spelling is available on the supported Node versions with `--permission`. */
const hasNodePermissionModel = process.allowedNodeEnvironmentFlags.has('--permission')

await test(
  'file-backed keys remain private under the Node permission model',
  { skip: unixOnly.skip || !hasNodePermissionModel },
  async () => {
    for (const umask of [0o000, 0o777]) {
      await withStorage(async (directory) => {
        const isMac = process.platform === 'darwin'
        if (isMac) {
          await grantInheritedRead(directory)
        }
        // Isolate the key's mode from recursive creation of its storage directory.
        await mkdir(join(directory, 'file'), { mode: 0o700 })
        const child = storeWithNodePermissions(await realpath(directory), isMac, umask)
        assert.ifError(child.error)
        assert.equal(child.status, 0, child.stderr)
        for (const path of [join(directory, '.keys.wrap'), join(directory, 'file', '.key')]) {
          const metadata = await stat(path)
          assert.equal(metadata.size, 32)
          assert.equal(metadata.mode & 0o777, 0o600)
          if (isMac) {
            assert.doesNotMatch(aclListing(path), /\n\s*\d+:/u)
          }
        }
      })
    }
  },
)

await test(
  'macOS filesystem-only permissions fail closed on inherited ACLs',
  { skip: process.platform !== 'darwin' || !hasNodePermissionModel },
  async () => {
    await withStorage(async (directory) => {
      await grantInheritedRead(directory)
      const child = storeWithNodePermissions(await realpath(directory), false, 0o000)
      assert.ifError(child.error)
      assert.equal(child.status, 1, child.stderr)
      assert.match(child.stderr, /FilesystemError/u)
      assert.match(child.stderr, /ERR_ACCESS_DENIED/u)
      assert.deepEqual(await readdir(directory), [])
    })
  },
)

await test('failed or interrupted key writes leave the destination intact', unixOnly, async () => {
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
  for (const scenario of ['partial', 'restrictive-umask', 'interrupt', 'chmod']) {
    await withStorage(async (directory) => {
      const physical = join(directory, 'storage')
      const nested = join(physical, 'nested')
      const alias = join(directory, 'alias')
      await mkdir(nested, { recursive: true, mode: 0o755 })
      await symlink(nested, alias)
      if (scenario === 'interrupt' && process.platform === 'darwin') {
        await grantInheritedRead(physical)
      }
      const child = spawnSync(
        '/bin/sh',
        [
          '-c',
          `umask "$1"; shift; ulimit -f 1 || exit; trap '' XFSZ; exec "$@"`,
          'vaultkeeper-test',
          scenario === 'restrictive-umask' ? '0777' : '000',
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
        const stage = join(physical, entry)
        const stagedFile = (await stat(stage)).isDirectory() ? join(stage, 'contents') : stage
        const metadata = await stat(stagedFile)
        assert.equal(metadata.size, 1)
        assert.equal(metadata.mode & 0o777, 0o600)
        if (process.platform === 'darwin') {
          assert.doesNotMatch(aclListing(stagedFile), /\n\s*\d+:/u)
        }
      }
    })
  }
})

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { missingCrates } from './release-reconciliation.mjs'

const npmUrl = 'https://registry.npmjs.org/%40vaultkeeper%2Fwasm/0.5.0'
const coreUrl = 'https://index.crates.io/va/ul/vaultkeeper-core'
const cliUrl = 'https://index.crates.io/va/ul/vaultkeeper-cli'

function releaseFixture(t, { cargo = '0.5.0', wasm = cargo } = {}) {
  const cwd = mkdtempSync(join(tmpdir(), 'vaultkeeper-release-'))
  t.after(() => rmSync(cwd, { recursive: true, force: true }))
  const git = (...args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim()
  git('init', '-q')
  git('config', 'user.name', 'Release Fixture')
  git('config', 'user.email', 'release@example.invalid')
  mkdirSync(join(cwd, 'packages/vaultkeeper-wasm'), { recursive: true })

  function commitVersions(cargoVersion, wasmVersion) {
    writeFileSync(
      join(cwd, 'Cargo.toml'),
      `[workspace]\r\n\r\n[workspace.package]\r\nversion = "${cargoVersion}"\r\n`,
    )
    writeFileSync(
      join(cwd, 'packages/vaultkeeper-wasm/package.json'),
      JSON.stringify({ version: wasmVersion }),
    )
    git('add', '.')
    git('commit', '-q', '--allow-empty', '-m', 'Fixture')
    return git('rev-parse', 'HEAD')
  }

  commitVersions('0.4.0', '0.4.0')
  const commit = commitVersions(cargo, wasm)
  // The Changesets checkout can move beyond the push under evaluation.
  commitVersions('0.6.0', '0.6.0')
  return { cwd, commit, publishedPackages: [] }
}

function registry({ npmStatus = 200, coreVersions = [], cliVersions = [], coreStatus } = {}) {
  const urls = []
  const request = async (url) => {
    urls.push(url)
    if (url === npmUrl) {
      return Response.json({ name: '@vaultkeeper/wasm', version: '0.5.0' }, { status: npmStatus })
    }
    assert.ok(url === coreUrl || url === cliUrl, `Unexpected URL: ${url}`)
    if (url === coreUrl && coreStatus) {
      return new Response(null, { status: coreStatus })
    }
    const name = url === coreUrl ? 'vaultkeeper-core' : 'vaultkeeper-cli'
    const versions = url === coreUrl ? coreVersions : cliVersions
    if (!versions.length) {
      return new Response(null, { status: 404 })
    }
    return new Response(
      versions.map((vers) => JSON.stringify({ name, vers, yanked: true })).join('\n'),
    )
  }
  return { request, urls }
}

test('a full rerun resumes at the missing CLI after npm and core published', async (t) => {
  const fixture = releaseFixture(t)
  const { request, urls } = registry({ coreVersions: ['0.4.0', '0.5.0'], cliVersions: ['0.4.0'] })
  assert.deepEqual(await missingCrates({ ...fixture, request }), ['vaultkeeper-cli'])
  assert.deepEqual(urls, [npmUrl, coreUrl, cliUrl])
})

test('an already complete release schedules neither crate', async (t) => {
  const { request } = registry({ coreVersions: ['0.5.0'], cliVersions: ['0.5.0'] })
  assert.deepEqual(await missingCrates({ ...releaseFixture(t), request }), [])
})

test('an ordinary run schedules neither crate and never queries the registries', async (t) => {
  const fixture = releaseFixture(t, { cargo: '0.4.0' })
  const { request, urls } = registry()
  const publishedPackages = [{ name: '@vaultkeeper/wasm', version: '0.4.0' }]
  assert.deepEqual(await missingCrates({ ...fixture, request, publishedPackages }), [])
  assert.deepEqual(urls, [])
})

test('a Cargo-only version bump cannot publish crates', async (t) => {
  const fixture = releaseFixture(t, { wasm: '0.4.0' })
  const { request, urls } = registry()
  assert.deepEqual(await missingCrates({ ...fixture, request }), [])
  assert.deepEqual(urls, [])
})

test('an unrelated npm publication cannot authorize publishing crates', async (t) => {
  const fixture = releaseFixture(t)
  const { request, urls } = registry({ npmStatus: 404 })
  const publishedPackages = [{ name: 'vaultkeeper', version: '0.5.0' }]
  assert.deepEqual(await missingCrates({ ...fixture, request, publishedPackages }), [])
  assert.deepEqual(urls, [npmUrl])
})

test('a fresh matching Changesets publication schedules both missing crates', async (t) => {
  const fixture = releaseFixture(t)
  const { request, urls } = registry()
  const publishedPackages = [{ name: '@vaultkeeper/wasm', version: '0.5.0' }]
  assert.deepEqual(await missingCrates({ ...fixture, request, publishedPackages }), [
    'vaultkeeper-core',
    'vaultkeeper-cli',
  ])
  assert.deepEqual(urls, [coreUrl, cliUrl])
})

test('registry errors fail the release instead of scheduling a publish', async (t) => {
  const { request } = registry({ coreStatus: 503 })
  await assert.rejects(missingCrates({ ...releaseFixture(t), request }), /HTTP 503/)
})

test('the workflow uses the reconciliation outputs for the job and each crate', () => {
  const workflow = readFileSync(
    new URL('../.github/workflows/release.yml', import.meta.url),
    'utf8',
  )
  assert.match(workflow, /run: node scripts\/release-reconciliation\.mjs >> "\$GITHUB_OUTPUT"/)
  assert.match(
    workflow,
    /publish-crates:\n[^\n]*\n[^\n]*\n    if: needs\.release\.outputs\.core-missing == 'true' \|\| needs\.release\.outputs\.cli-missing == 'true'/,
  )
  assert.match(
    workflow,
    /name: Publish vaultkeeper-core\n\s+if: needs\.release\.outputs\.core-missing == 'true'/,
  )
  assert.match(
    workflow,
    /name: Publish vaultkeeper-cli[^\n]*\n\s+if: needs\.release\.outputs\.cli-missing == 'true'/,
  )
})

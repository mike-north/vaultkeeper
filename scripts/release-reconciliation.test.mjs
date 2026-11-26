import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { missingCrates } from './release-reconciliation.mjs'

const npmUrl = 'https://registry.npmjs.org/%40vaultkeeper%2Fwasm/0.5.0'
const provenanceUrl = 'https://registry.npmjs.org/-/npm/v1/attestations/%40vaultkeeper%2Fwasm@0.5.0'
const coreUrl = 'https://index.crates.io/va/ul/vaultkeeper-core'
const cliUrl = 'https://index.crates.io/va/ul/vaultkeeper-cli'
const provenanceType = 'https://slsa.dev/provenance/v1'
const tarballDigest = Buffer.alloc(64, 1)
const noRelease = { missing: [], source: null }

// The event boundaries stay fixed while later commits can change the working checkout.
function releaseFixture(
  t,
  { cargo = '0.5.0', wasm = cargo, laterTip = false, splitBump = false, manifestEdit = false } = {},
) {
  const cwd = mkdtempSync(join(tmpdir(), 'vaultkeeper-release-'))
  t.after(() => rmSync(cwd, { recursive: true, force: true }))
  const git = (...args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim()
  git('init', '-q')
  git('config', 'user.name', 'Release Fixture')
  git('config', 'user.email', 'release@example.invalid')
  mkdirSync(join(cwd, 'packages/vaultkeeper-wasm'), { recursive: true })
  const wasmManifest = join(cwd, 'packages/vaultkeeper-wasm/package.json')

  // Return a SHA that remains usable after another commit changes the working tree.
  function commitFixture() {
    git('add', '.')
    git('commit', '-q', '--allow-empty', '-m', 'Fixture')
    return git('rev-parse', 'HEAD')
  }

  function commitVersions(cargoVersion, wasmVersion) {
    writeFileSync(
      join(cwd, 'Cargo.toml'),
      `[workspace]\r\n\r\n[workspace.package]\r\nversion = "${cargoVersion}"\r\n`,
    )
    writeFileSync(wasmManifest, JSON.stringify({ version: wasmVersion }))
    return commitFixture()
  }

  const before = commitVersions('0.4.0', '0.4.0')
  if (splitBump) commitVersions(cargo, '0.4.0')
  const releaseCommit = commitVersions(cargo, wasm)
  let docsBefore = releaseCommit
  if (manifestEdit) {
    writeFileSync(wasmManifest, JSON.stringify({ version: wasm, description: 'WASM SDK' }))
    docsBefore = commitFixture()
  }
  let commit = docsBefore
  if (laterTip) {
    writeFileSync(join(cwd, 'README.md'), 'Documentation follow-up\n')
    commit = commitFixture()
  }
  // The Changesets checkout can move beyond the push under evaluation.
  const laterCommit = commitVersions('0.6.0', '0.6.0')
  return { cwd, before, commit, releaseCommit, docsBefore, laterCommit, publishedPackages: [] }
}

test('recovery binds missing crates to the npm source commit', async (t) => {
  const fixture = releaseFixture(t, { laterTip: true })
  const { request } = registry({ gitHead: fixture.releaseCommit, coreVersions: ['0.5.0'] })
  assert.deepEqual(await missingCrates({ ...fixture, request }), {
    missing: ['vaultkeeper-cli'],
    source: fixture.releaseCommit,
  })
})

test('recovery rejects absent or unrelated npm source evidence', async (t) => {
  const fixture = releaseFixture(t)
  for (const gitHead of [undefined, 'f'.repeat(40), fixture.before, fixture.laterCommit]) {
    const { request, urls } = registry({ gitHead })
    await assert.rejects(missingCrates({ ...fixture, request }), /source|commit/i)
    assert.deepEqual(urls, [npmUrl])
  }
})

test('one push containing the bump and a docs follow-up supports publication and a full rerun', async (t) => {
  const fixture = releaseFixture(t, { laterTip: true })
  const publishedPackages = [{ name: '@vaultkeeper/wasm', version: '0.5.0' }]
  const initial = registry({ coreVersions: ['0.5.0'] })
  assert.deepEqual(
    await missingCrates({ ...fixture, request: initial.request, publishedPackages }),
    { missing: ['vaultkeeper-cli'], source: fixture.commit },
  )
  assert.deepEqual(initial.urls, [coreUrl, cliUrl])
  const rerun = registry({ gitHead: fixture.commit, coreVersions: ['0.5.0'] })
  assert.deepEqual(await missingCrates({ ...fixture, request: rerun.request }), {
    missing: ['vaultkeeper-cli'],
    source: fixture.commit,
  })
  assert.deepEqual(rerun.urls, [npmUrl, coreUrl, cliUrl])
})

test('a separate docs push can finish a fresh WASM release when the bump run was skipped', async (t) => {
  const fixture = releaseFixture(t, { laterTip: true })
  // The pending bump run was replaced. Changesets published WASM on the docs push.
  const { request, urls } = registry({ npmStatus: 404 })
  const publishedPackages = [{ name: '@vaultkeeper/wasm', version: '0.5.0' }]
  assert.deepEqual(
    await missingCrates({ ...fixture, before: fixture.releaseCommit, request, publishedPackages }),
    { missing: ['vaultkeeper-core', 'vaultkeeper-cli'], source: fixture.commit },
  )
  assert.deepEqual(urls, [coreUrl, cliUrl])
})

test('a version-preserving manifest edit between pushes does not hide the synchronized bump', async (t) => {
  const fixture = releaseFixture(t, { laterTip: true, manifestEdit: true })
  const { request } = registry({ gitHead: fixture.commit, coreVersions: ['0.5.0'] })
  assert.deepEqual(
    await missingCrates({ ...fixture, before: fixture.docsBefore, request, rerun: true }),
    { missing: ['vaultkeeper-cli'], source: fixture.commit },
  )
})

// npm's trusted-publishing provenance ties the exact tarball to the release workflow's commit.
function provenance(
  commit,
  { digest = tarballDigest.toString('hex'), ref = 'refs/heads/main' } = {},
) {
  const repository = 'https://github.com/mike-north/vaultkeeper'
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'pkg:npm/%40vaultkeeper/wasm@0.5.0', digest: { sha512: digest } }],
    predicateType: provenanceType,
    predicate: {
      buildDefinition: {
        buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
        externalParameters: {
          workflow: { repository, ref, path: '.github/workflows/release.yml' },
        },
        resolvedDependencies: [{ uri: `git+${repository}@${ref}`, digest: { gitCommit: commit } }],
      },
    },
  }
  const payload = Buffer.from(JSON.stringify(statement)).toString('base64')
  return {
    attestations: [{ predicateType: provenanceType, bundle: { dsseEnvelope: { payload } } }],
  }
}

test('a trusted npm release with provenance and no gitHead can resume publishing', async (t) => {
  const fixture = releaseFixture(t, { laterTip: true })
  const { request, urls } = registry({
    coreVersions: ['0.5.0'],
    attestations: provenance(fixture.releaseCommit),
  })
  assert.deepEqual(await missingCrates({ ...fixture, request }), {
    missing: ['vaultkeeper-cli'],
    source: fixture.releaseCommit,
  })
  assert.deepEqual(urls, [npmUrl, provenanceUrl, coreUrl, cliUrl])
})

test('after the separate docs push published WASM, only its rerun can recover the missing CLI', async (t) => {
  const fixture = releaseFixture(t, { laterTip: true })
  const attestations = provenance(fixture.commit)
  const bump = registry({ attestations })
  await assert.rejects(
    missingCrates({
      ...fixture,
      commit: fixture.releaseCommit,
      request: bump.request,
      rerun: true,
    }),
    /outside the release push/,
  )
  assert.deepEqual(bump.urls, [npmUrl, provenanceUrl])

  const docs = registry({ attestations, coreVersions: ['0.5.0'] })
  assert.deepEqual(
    await missingCrates({
      ...fixture,
      before: fixture.releaseCommit,
      request: docs.request,
      rerun: true,
    }),
    { missing: ['vaultkeeper-cli'], source: fixture.commit },
  )
  assert.deepEqual(docs.urls, [npmUrl, provenanceUrl, coreUrl, cliUrl])
})

test('npm provenance must identify this tarball, workflow, and push', async (t) => {
  const fixture = releaseFixture(t)
  for (const attestations of [
    provenance(fixture.commit, { digest: '0'.repeat(128) }),
    provenance(fixture.commit, { ref: 'refs/heads/other' }),
    provenance(fixture.laterCommit),
  ]) {
    const { request, urls } = registry({ attestations })
    await assert.rejects(missingCrates({ ...fixture, request }), /source|commit/i)
    assert.deepEqual(urls, [npmUrl, provenanceUrl])
  }
})

// The registry fixtures mirror the exact-version npm endpoint and the crates.io sparse index.
function registry({
  npmStatus = 200,
  coreVersions = [],
  cliVersions = [],
  coreStatus,
  gitHead,
  attestations,
} = {}) {
  const urls = []
  const request = async (url) => {
    urls.push(url)
    if (url === npmUrl) {
      const dist = attestations && {
        integrity: `sha512-${tarballDigest.toString('base64')}`,
        attestations: { provenance: { predicateType: provenanceType } },
      }
      return Response.json(
        { name: '@vaultkeeper/wasm', version: '0.5.0', gitHead, dist },
        { status: npmStatus },
      )
    }
    if (url === provenanceUrl) return Response.json(attestations)
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
  const { request, urls } = registry({
    gitHead: fixture.commit,
    coreVersions: ['0.4.0', '0.5.0'],
    cliVersions: ['0.4.0'],
  })
  assert.deepEqual(await missingCrates({ ...fixture, request }), {
    missing: ['vaultkeeper-cli'],
    source: fixture.commit,
  })
  assert.deepEqual(urls, [npmUrl, coreUrl, cliUrl])
})

test('an already complete release schedules neither crate', async (t) => {
  const fixture = releaseFixture(t)
  const { request } = registry({
    gitHead: fixture.commit,
    coreVersions: ['0.5.0'],
    cliVersions: ['0.5.0'],
  })
  assert.deepEqual((await missingCrates({ ...fixture, request })).missing, [])
})

test('an ordinary run schedules neither crate and never queries the registries', async (t) => {
  const fixture = releaseFixture(t, { cargo: '0.4.0' })
  const { request, urls } = registry()
  const publishedPackages = [{ name: '@vaultkeeper/wasm', version: '0.4.0' }]
  assert.deepEqual(await missingCrates({ ...fixture, request, publishedPackages }), noRelease)
  assert.deepEqual(urls, [])
})

test('an ordinary push after the release cannot recover an earlier push', async (t) => {
  const fixture = releaseFixture(t, { laterTip: true })
  const { request, urls } = registry({ gitHead: fixture.releaseCommit })
  assert.deepEqual(
    await missingCrates({ ...fixture, before: fixture.releaseCommit, request }),
    noRelease,
  )
  assert.deepEqual(urls, [])

  const rerun = registry({ gitHead: fixture.releaseCommit })
  assert.deepEqual(
    await missingCrates({
      ...fixture,
      before: fixture.releaseCommit,
      request: rerun.request,
      rerun: true,
    }),
    noRelease,
  )
  assert.deepEqual(rerun.urls, [npmUrl])
})

test('a Cargo-only version bump cannot publish crates', async (t) => {
  const fixture = releaseFixture(t, { wasm: '0.4.0' })
  const { request, urls } = registry()
  assert.deepEqual(await missingCrates({ ...fixture, request }), noRelease)
  assert.deepEqual(urls, [])
})

test('a same-version push cannot treat separate Cargo and WASM version changes as a synchronized bump', async (t) => {
  const fixture = releaseFixture(t, { laterTip: true, splitBump: true })
  const { request, urls } = registry()
  const publishedPackages = [{ name: '@vaultkeeper/wasm', version: '0.5.0' }]
  assert.deepEqual(
    await missingCrates({ ...fixture, before: fixture.releaseCommit, request, publishedPackages }),
    noRelease,
  )
  assert.deepEqual(urls, [])
})

test('an unrelated npm publication cannot authorize publishing crates', async (t) => {
  const fixture = releaseFixture(t)
  const { request, urls } = registry({ npmStatus: 404 })
  const publishedPackages = [{ name: 'vaultkeeper', version: '0.5.0' }]
  assert.deepEqual(await missingCrates({ ...fixture, request, publishedPackages }), noRelease)
  assert.deepEqual(urls, [npmUrl])
})

test('a fresh matching Changesets publication schedules both missing crates', async (t) => {
  const fixture = releaseFixture(t)
  const { request, urls } = registry()
  const publishedPackages = [{ name: '@vaultkeeper/wasm', version: '0.5.0' }]
  assert.deepEqual(await missingCrates({ ...fixture, request, publishedPackages }), {
    missing: ['vaultkeeper-core', 'vaultkeeper-cli'],
    source: fixture.commit,
  })
  assert.deepEqual(urls, [coreUrl, cliUrl])
})

test('registry errors fail the release instead of scheduling a publish', async (t) => {
  const fixture = releaseFixture(t)
  const { request } = registry({ gitHead: fixture.commit, coreStatus: 503 })
  await assert.rejects(missingCrates({ ...fixture, request }), /HTTP 503/)
})

// Exercise the script with the same environment and output contract as the workflow step.
function reconciliationOutput({ cwd, before, commit, source, attempt }) {
  const registryMock = join(cwd, 'registry.mjs')
  writeFileSync(
    registryMock,
    `globalThis.fetch = async (url) => {
    if (url === ${JSON.stringify(npmUrl)}) {
      return Response.json({ name: '@vaultkeeper/wasm', version: '0.5.0', gitHead: '${source}' })
    }
    if (url === ${JSON.stringify(coreUrl)}) {
      return Response.json({ name: 'vaultkeeper-core', vers: '0.5.0' })
    }
    if (url === ${JSON.stringify(cliUrl)}) return new Response(null, { status: 404 })
    throw new TypeError('Unexpected registry URL')
  }`,
  )
  const script = fileURLToPath(new URL('./release-reconciliation.mjs', import.meta.url))
  return execFileSync(process.execPath, ['--import', registryMock, script], {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      GITHUB_SHA: commit,
      PUSH_BEFORE: before,
      PUBLISHED_PACKAGES: '[]',
      GITHUB_RUN_ATTEMPT: attempt,
    },
  })
}

test('the reconciliation entry point emits the validated source and both crate flags', (t) => {
  const fixture = releaseFixture(t, { laterTip: true })
  const { releaseCommit } = fixture
  assert.equal(
    reconciliationOutput({ ...fixture, source: releaseCommit, attempt: '1' }),
    `source=${releaseCommit}\ncore-missing=false\ncli-missing=true\n`,
  )
})

test('the reconciliation entry point recognizes a full rerun of the separate docs push', (t) => {
  const fixture = releaseFixture(t, { laterTip: true })
  const { commit, releaseCommit } = fixture
  assert.equal(
    reconciliationOutput({ ...fixture, before: releaseCommit, source: commit, attempt: '2' }),
    `source=${commit}\ncore-missing=false\ncli-missing=true\n`,
  )
})

test('the workflow provides the original push and checks out the validated source to publish', () => {
  const workflow = readFileSync(
    new URL('../.github/workflows/release.yml', import.meta.url),
    'utf8',
  )
  assert.match(workflow, /run: node scripts\/release-reconciliation\.mjs >> "\$GITHUB_OUTPUT"/)
  assert.match(workflow, /PUSH_BEFORE: \$\{\{ github\.event\.before \}\}/)
  assert.match(workflow, /source: \$\{\{ steps\.release-state\.outputs\.source \}\}/)
  const releaseJob = workflow.split('\n  release:\n')[1]?.split('\n  publish-crates:\n')[0]
  assert.match(
    releaseJob,
    /uses: actions\/checkout@v4\n\s+with:\n\s+ref: \$\{\{ github\.sha \}\}\n(?:\s+#[^\n]*\n)*\s+fetch-depth: 0/,
  )
  const publishJob = workflow.split('\n  publish-crates:\n')[1]
  assert.match(
    publishJob,
    /uses: actions\/checkout@v4\n\s+with:\n\s+ref: \$\{\{ needs\.release\.outputs\.source \}\}/,
  )
  assert.match(workflow, /core-missing: \$\{\{ steps\.release-state\.outputs\.core-missing \}\}/)
  assert.match(workflow, /cli-missing: \$\{\{ steps\.release-state\.outputs\.cli-missing \}\}/)
  assert.match(
    workflow,
    /publish-crates:\n[^\n]*\n[^\n]*\n    if: needs\.release\.outputs\.source != '' && \(needs\.release\.outputs\.core-missing == 'true' \|\| needs\.release\.outputs\.cli-missing == 'true'\)/,
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

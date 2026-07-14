/**
 * Fails if docs/api/ (api-documenter markdown output) is stale relative to
 * the built API — mirrors the check:api-report pattern (api-extractor run
 * without --local) but for api-documenter, which has no built-in check mode.
 *
 * Regenerates api-documenter output into a temp directory from the already-
 * collected tmp/api-documenter/*.api.json files (produced by
 * `generate:api-report`/`check:api-report`, which must run first — see
 * scripts/collect-api-json.mjs) and diffs it file-by-file against the
 * committed docs/api/. Any content difference, added file, or removed file
 * is staleness.
 */
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const collectedDir = 'tmp/api-documenter'
const committedDir = 'docs/api'

try {
  readdirSync(collectedDir)
} catch (err) {
  const reason = err instanceof Error ? err.message : String(err)
  throw new Error(
    `Cannot read ${collectedDir} (${reason}). Run "pnpm build && pnpm generate:api-report && node scripts/collect-api-json.mjs" first.`,
  )
}

const tempDir = mkdtempSync(join(tmpdir(), 'vaultkeeper-api-docs-'))

try {
  execFileSync('api-documenter', ['markdown', '-i', collectedDir, '-o', tempDir], {
    stdio: 'inherit',
  })

  let committedFiles
  try {
    committedFiles = new Set(readdirSync(committedDir))
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err)
    throw new Error(
      `Cannot read ${committedDir} (${reason}). Run "pnpm generate:api-docs" and commit the result.`,
    )
  }
  const generatedFiles = new Set(readdirSync(tempDir))
  const allFiles = new Set([...committedFiles, ...generatedFiles])

  const stale = []
  for (const file of allFiles) {
    const inCommitted = committedFiles.has(file)
    const inGenerated = generatedFiles.has(file)

    if (inCommitted && !inGenerated) {
      stale.push(`docs/api/${file} is committed but no longer generated`)
      continue
    }
    if (!inCommitted && inGenerated) {
      stale.push(`docs/api/${file} is generated but not committed`)
      continue
    }

    const committedContent = readFileSync(join(committedDir, file), 'utf8')
    const generatedContent = readFileSync(join(tempDir, file), 'utf8')
    if (committedContent !== generatedContent) {
      stale.push(`docs/api/${file} differs from the regenerated output`)
    }
  }

  if (stale.length > 0) {
    console.error(`docs/api/ is stale (${String(stale.length)} file(s)):\n`)
    for (const message of stale) {
      console.error(`  - ${message}`)
    }
    console.error('\nRun "pnpm generate:api-docs" and commit the result.')
    process.exitCode = 1
  } else {
    console.log('docs/api/ is up to date.')
  }
} finally {
  rmSync(tempDir, { recursive: true, force: true })
}

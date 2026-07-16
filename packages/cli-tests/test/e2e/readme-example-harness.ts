/**
 * Harness for validating the fenced examples in the *shipped* READMEs against
 * the *built* packages, so a copy-pasteable example that no longer works fails
 * CI instead of a real user (issue #217).
 *
 * Two validation modes, keyed off the fence language:
 *
 * - **Shell** fences (`sh` / `bash` / `shell` / `console`) are *executed*
 *   verbatim through real `bash -euo pipefail` in an isolated config dir +
 *   `file` backend, with a `vaultkeeper` shim on `PATH`. The command sequence
 *   must exit `0`. Because it runs the *actual* shell, it reproduces shell
 *   byte-semantics — e.g. it catches the `printf '%s'` (no newline) vs `<<<`
 *   (trailing newline) sign/verify mismatch of issue #214, which makes the
 *   detached signature verify fail with exit `3`.
 * - **TypeScript/JavaScript** fences (`ts` / `js`) in the two *library*
 *   READMEs are *type-checked* under the repo's strict NodeNext config against
 *   each package's built `.d.ts`, so a snippet with a wrong signature (e.g. a
 *   2-arg `setup()`) fails CI.
 *
 * ## Running a TS/JS fence (not just type-checking it)
 *
 * A type-only check misses runtime-only breakage: a snippet can compile yet
 * throw before it does anything useful — e.g. calling `setup()` on a secret it
 * forgot to `store()` first (issue #227). Mark a *self-contained* TS/JS fence
 * with `<!-- readme-example: run -->` and it is additionally *executed* against
 * the built package with `tsx`, in an isolated `VAULTKEEPER_CONFIG_DIR`, with
 * the network boundary stubbed (`globalThis.fetch` returns a canned 200 without
 * leaving the process). The run must exit `0`, so a fence that throws on
 * argument construction — or on a missing store/setup step — before reaching the
 * stubbed `fetch` fails CI. A `run` fence must be self-contained (its own
 * `import` + `VaultKeeper.init()`); it is still type-checked as well.
 *
 * ## Opting a fence out
 *
 * Many fenced examples are intentionally illustrative fragments, not runnable
 * programs (they reference a `vault` bound in a previous fence, a placeholder
 * path like `/usr/local/bin/my-tool`, or a network endpoint). Mark such a fence
 * with an HTML comment preceding its opening fence — the extractor scans backward
 * over any intervening blank lines, so the marker need not be immediately adjacent:
 *
 * ```md
 * <!-- readme-example: skip - references a vault from an earlier fence -->
 * ```ts
 * await vault.exec(token, { ... })
 * ```
 * ```
 *
 * The text after `skip` is a free-form reason (optional but encouraged).
 * Package-manager install lines (`pnpm add`, `npm install`, `cargo install`,
 * …) are auto-skipped without a marker because they need network access.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/217
 * @see https://github.com/mike-north/vaultkeeper/issues/214
 */
import { spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

/** Repo root, resolved from this file (packages/cli-tests/test/e2e/). */
export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..')

/** Languages whose fences are executed as shell scripts. */
const SHELL_LANGS = new Set(['sh', 'bash', 'shell', 'console'])
/** Languages whose fences are type-checked. */
const TS_LANGS = new Set(['ts', 'typescript'])
const JS_LANGS = new Set(['js', 'javascript'])

/** A fenced code block extracted from a README. */
export interface Fence {
  /** README this fence came from, repo-relative (e.g. `packages/cli/README.md`). */
  readme: string
  /** Lowercased fence info-string language (e.g. `sh`, `ts`). */
  lang: string
  /** Fence body (without the ``` delimiters). */
  code: string
  /** 1-based line number of the opening ``` fence. */
  startLine: number
  /** True if a `readme-example: skip` marker precedes the fence. */
  skipped: boolean
  /** The free-form reason from the skip marker, if any. */
  skipReason: string | undefined
  /** True if a `readme-example: run` marker precedes the fence. */
  run: boolean
  /** The free-form reason from the run marker, if any. */
  runReason: string | undefined
}

const SKIP_MARKER = /<!--\s*readme-example:\s*skip\b[ \t-]*(.*?)\s*-->/i
const RUN_MARKER = /<!--\s*readme-example:\s*run\b[ \t-]*(.*?)\s*-->/i

/**
 * Extract every fenced code block from `markdown`, recording each fence's
 * language, body, opening line, and whether a `readme-example: skip` HTML
 * comment marker immediately precedes it (scanning back over blank lines).
 */
export function extractFences(markdown: string, readme: string): Fence[] {
  const lines = markdown.split('\n')
  const out: Fence[] = []
  let i = 0
  while (i < lines.length) {
    const open = /^```(\S*)/.exec((lines[i] ?? '').trim())
    if (open === null) {
      i += 1
      continue
    }
    const lang = (open[1] ?? '').toLowerCase()
    const startLine = i + 1
    const body: string[] = []
    let j = i + 1
    while (j < lines.length && !(lines[j] ?? '').trim().startsWith('```')) {
      body.push(lines[j] ?? '')
      j += 1
    }
    // Look back over blank lines for a skip/run marker on the preceding line.
    let k = i - 1
    while (k >= 0 && (lines[k] ?? '').trim() === '') k -= 1
    const markerLine = k >= 0 ? (lines[k] ?? '') : ''
    const skipMarker = SKIP_MARKER.exec(markerLine)
    // Skip takes precedence over run: an explicitly opted-out fence must never
    // execute, even if the same marker line also carries a `run` marker.
    const runMarker = skipMarker !== null ? null : RUN_MARKER.exec(markerLine)
    const reasonOf = (m: RegExpExecArray): string | undefined =>
      m[1] === undefined || m[1] === '' ? undefined : m[1]
    out.push({
      readme,
      lang,
      code: body.join('\n'),
      startLine,
      skipped: skipMarker !== null,
      skipReason: skipMarker !== null ? reasonOf(skipMarker) : undefined,
      run: runMarker !== null,
      runReason: runMarker !== null ? reasonOf(runMarker) : undefined,
    })
    i = j + 1
  }
  return out
}

/** True when `fence` is a shell fence. */
export function isShellFence(fence: Fence): boolean {
  return SHELL_LANGS.has(fence.lang)
}

/** True when `fence` is a TypeScript or JavaScript fence. */
export function isCodeFence(fence: Fence): boolean {
  return TS_LANGS.has(fence.lang) || JS_LANGS.has(fence.lang)
}

const INSTALL_LINE = /^\s*(?:pnpm|npm|yarn|cargo)\s+(?:add|install|i|dlx)\b/

/**
 * A shell fence is auto-skipped (no marker required) when it only demonstrates
 * a package-manager install — those need network access and are not part of the
 * runnable walkthroughs.
 */
export function isInstallOnlyFence(fence: Fence): boolean {
  const cmds = fence.code
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'))
  return cmds.length > 0 && cmds.every((l) => INSTALL_LINE.test(l))
}

/** Result of executing a shell fence. */
export interface ShellRunResult {
  exitCode: number
  stdout: string
  stderr: string
}

const DEFAULT_CONFIG = {
  version: 1,
  backends: [{ type: 'file', enabled: true }],
  keyRotation: { gracePeriodDays: 7 },
  defaults: { ttlMinutes: 60, trustTier: 3 },
}

/** Resolve the CLI entry point: prefer the built `dist/bin.js`, else `src/bin.ts` via tsx. */
function resolveCliCommand(): { runner: string; entry: string } {
  const distBin = path.join(REPO_ROOT, 'packages', 'cli', 'dist', 'bin.js')
  if (fs.existsSync(distBin)) return { runner: process.execPath, entry: distBin }
  const tsx = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx')
  return { runner: tsx, entry: path.join(REPO_ROOT, 'packages', 'cli', 'src', 'bin.ts') }
}

/**
 * Execute a shell fence's body verbatim through `bash -euo pipefail` in a
 * fresh isolated environment: a temp config dir seeded with a `file`-backend
 * `config.json`, a temp working directory, and a `vaultkeeper` shim on `PATH`
 * that invokes the real CLI. Returns the shell's exit code and output.
 */
export function runShellFence(fence: Fence): ShellRunResult {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vk-readme-'))
  try {
    const configDir = path.join(root, 'config')
    const workDir = path.join(root, 'work')
    const binDir = path.join(root, 'bin')
    fs.mkdirSync(path.join(configDir, 'secrets'), { recursive: true })
    fs.mkdirSync(workDir, { recursive: true })
    fs.mkdirSync(binDir, { recursive: true })
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify(DEFAULT_CONFIG, null, 2) + '\n', {
      encoding: 'utf8',
      mode: 0o600,
    })

    const { runner, entry } = resolveCliCommand()
    const shim = path.join(binDir, 'vaultkeeper')
    // Quote runner/entry so paths with spaces survive; forward all args + stdin.
    fs.writeFileSync(shim, `#!/usr/bin/env bash\nexec ${JSON.stringify(runner)} ${JSON.stringify(entry)} "$@"\n`, {
      encoding: 'utf8',
      mode: 0o755,
    })

    // Build a minimal, deterministic environment instead of inheriting the full
    // parent env: README fences run verbatim, so they must not depend on ambient
    // VAULTKEEPER_* toggles (which would make the example non-reproducible), and CI
    // secrets must never be exposed to a fence that forwards env. Only HOME +
    // VAULTKEEPER_CONFIG_DIR are set explicitly; a small locale/tmp allowlist is
    // carried through when present so tools behave normally.
    const env: NodeJS.ProcessEnv = {
      PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ''}`,
      HOME: root,
      VAULTKEEPER_CONFIG_DIR: configDir,
    }
    for (const key of ['LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'TERM']) {
      const value = process.env[key]
      if (value !== undefined) {
        env[key] = value
      }
    }

    const result = spawnSync('bash', ['--noprofile', '--norc', '-euo', 'pipefail', '-c', fence.code], {
      cwd: workDir,
      env,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60_000,
    })
    // spawnSync could not start bash at all (missing binary, permission, etc.):
    // status and signal are both null. Fail loudly instead of reporting a vacuous
    // exitCode 0 that would let the fence check pass without running anything.
    if (result.error) {
      throw new Error(
        `Failed to run shell fence from ${fence.readme}:${String(fence.startLine)}: ${result.error.message}`,
      )
    }
    return {
      exitCode: result.status ?? (result.signal !== null ? 1 : 0),
      stdout: result.stdout,
      stderr: result.stderr,
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
}

/** Result of type-checking a TS/JS fence. */
export interface TypecheckResult {
  exitCode: number
  output: string
}

const TSCONFIG = {
  compilerOptions: {
    target: 'ES2022',
    module: 'NodeNext',
    moduleResolution: 'NodeNext',
    strict: true,
    skipLibCheck: false,
    noEmit: true,
    // A realistic consumer environment: the READMEs instruct users to install
    // @types/node (the public API references Buffer/process), so make it
    // available here rather than the matrix's deliberately-bare `types: []`.
    types: ['node'],
    allowJs: true,
    checkJs: true,
  },
}

/**
 * Type-check a TS/JS fence against the built package types. The snippet is
 * written into `packages/cli-tests/` (whose `node_modules` links the workspace
 * packages) so NodeNext resolution finds each package's built `.d.ts` through
 * its `exports` map, exactly as an external consumer would.
 */
export function typecheckCodeFence(fence: Fence): TypecheckResult {
  const scratch = fs.mkdtempSync(path.join(REPO_ROOT, 'packages', 'cli-tests', '.readme-tc-'))
  try {
    const ext = JS_LANGS.has(fence.lang) ? 'js' : 'ts'
    fs.writeFileSync(path.join(scratch, `snippet.${ext}`), fence.code, 'utf8')
    fs.writeFileSync(
      path.join(scratch, 'tsconfig.json'),
      JSON.stringify({ ...TSCONFIG, include: [`snippet.${ext}`] }, null, 2),
      'utf8',
    )
    const tsc = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsc')
    const result = spawnSync(tsc, ['-p', path.join(scratch, 'tsconfig.json')], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 120_000,
    })
    // spawnSync could not start tsc at all (missing/non-executable binary, etc.):
    // surface the underlying error instead of a silent, hard-to-diagnose failure.
    if (result.error) {
      throw new Error(
        `Failed to run tsc for a TS/JS fence: ${result.error.message}`,
      )
    }
    return {
      exitCode: result.status ?? 1,
      output: `${result.stdout}${result.stderr}`,
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true })
  }
}

/** Result of executing a `run`-marked TS/JS fence. */
export interface RunResult {
  exitCode: number
  stdout: string
  stderr: string
}

/**
 * The network-stub preload installed before a `run` fence executes. Replaces
 * `globalThis.fetch` with a canned 200 response so execution stops at the fetch
 * boundary instead of making a real request — a fence that constructs its fetch
 * arguments wrong, or omits a required `store()`/`setup()`, throws *before* this
 * is reached and the process exits non-zero. Kept as a plain `.mjs` module (no
 * TS transform) so it loads via node's `--import` before the ESM snippet runs.
 */
const RUN_FETCH_STUB = [
  "globalThis.fetch = () =>",
  "  Promise.resolve(new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }))",
  '',
].join('\n')

/**
 * Execute a `run`-marked TS/JS fence against the *built* package. The snippet is
 * written into `packages/cli-tests/` (so NodeNext resolution finds each package's
 * built output through its `exports` map, exactly as an external consumer would)
 * and run with `tsx`, with {@link RUN_FETCH_STUB} preloaded so the network is
 * never touched. It runs in a fresh, ambient-free `VAULTKEEPER_CONFIG_DIR` so
 * `store()`/`setup()` are hermetic and reproducible. Returns the process exit
 * code and output; a non-zero exit means the documented example threw at
 * runtime — the class of bug a type-only check misses (issue #227).
 */
export function runCodeFence(fence: Fence): RunResult {
  const scratch = fs.mkdtempSync(path.join(REPO_ROOT, 'packages', 'cli-tests', '.readme-run-'))
  const configRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'vk-readme-run-'))
  try {
    const ext = JS_LANGS.has(fence.lang) ? 'js' : 'ts'
    const snippet = path.join(scratch, `snippet.${ext}`)
    fs.writeFileSync(snippet, fence.code, 'utf8')
    const preload = path.join(scratch, 'network-stub.mjs')
    fs.writeFileSync(preload, RUN_FETCH_STUB, 'utf8')

    const configDir = path.join(configRoot, 'config')
    fs.mkdirSync(configDir, { recursive: true })
    // Ambient-free env (mirrors runShellFence): a run fence must not depend on
    // the developer's VAULTKEEPER_* toggles, and CI secrets must not leak in.
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH ?? '',
      HOME: configRoot,
      VAULTKEEPER_CONFIG_DIR: configDir,
    }
    for (const key of ['LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'TERM']) {
      const value = process.env[key]
      if (value !== undefined) {
        env[key] = value
      }
    }

    const tsx = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx')
    const result = spawnSync(tsx, ['--import', pathToFileURL(preload).href, snippet], {
      cwd: REPO_ROOT,
      env,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 120_000,
    })
    // spawnSync could not start tsx at all: surface it instead of a vacuous pass.
    if (result.error) {
      throw new Error(
        `Failed to run a run-marked fence from ${fence.readme}:${String(fence.startLine)}: ${result.error.message}`,
      )
    }
    return {
      exitCode: result.status ?? (result.signal !== null ? 1 : 0),
      stdout: result.stdout,
      stderr: result.stderr,
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true })
    fs.rmSync(configRoot, { recursive: true, force: true })
  }
}

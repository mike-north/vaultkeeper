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
 * ## Opting a fence out
 *
 * Many fenced examples are intentionally illustrative fragments, not runnable
 * programs (they reference a `vault` bound in a previous fence, a placeholder
 * path like `/usr/local/bin/my-tool`, or a network endpoint). Mark such a fence
 * with an HTML comment on the line immediately preceding its opening fence:
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
import { fileURLToPath } from 'node:url'

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
}

const SKIP_MARKER = /<!--\s*readme-example:\s*skip\b[ \t-]*(.*?)\s*-->/i

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
    // Look back over blank lines for a skip marker on the preceding line.
    let k = i - 1
    while (k >= 0 && (lines[k] ?? '').trim() === '') k -= 1
    const marker = k >= 0 ? SKIP_MARKER.exec(lines[k] ?? '') : null
    out.push({
      readme,
      lang,
      code: body.join('\n'),
      startLine,
      skipped: marker !== null,
      skipReason: marker !== null ? (marker[1] === undefined || marker[1] === '' ? undefined : marker[1]) : undefined,
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

    const env: NodeJS.ProcessEnv = {
      ...process.env,
      PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ''}`,
      HOME: root,
      VAULTKEEPER_CONFIG_DIR: configDir,
    }

    const result = spawnSync('bash', ['--noprofile', '--norc', '-euo', 'pipefail', '-c', fence.code], {
      cwd: workDir,
      env,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60_000,
    })
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
    return {
      exitCode: result.status ?? 1,
      output: `${result.stdout}${result.stderr}`,
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true })
  }
}

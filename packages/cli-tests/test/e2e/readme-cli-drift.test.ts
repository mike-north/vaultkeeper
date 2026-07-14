/**
 * Drift guard: every flag used in a `vaultkeeper` CLI example in the root
 * README must exist in that command's real `--help` output.
 *
 * This prevents the README's command examples from silently drifting away from
 * the shipped Node CLI surface (e.g. documenting a `--token` or `--path` flag
 * that no command accepts). It parses the shell code fences in README.md,
 * extracts each `vaultkeeper <command> ... --flag` invocation, and checks the
 * long flags against the flags printed by `vaultkeeper <command> --help`.
 *
 * The Node CLI (`@vaultkeeper/cli`) is canonical for the README per the issue.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/62
 */
import { readFileSync } from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

const SHELL_FENCE_LANGS = new Set(['sh', 'bash', 'shell', 'console'])

/** A single `vaultkeeper <command>` invocation parsed from a README fence. */
interface CliInvocation {
  /** The subcommand name (e.g. `exec`, `approve`). */
  command: string
  /** Long/short flags used before any `--` separator (e.g. `--secret`). */
  flags: string[]
  /** 1-based README line number, for actionable failure messages. */
  line: number
  /** The trimmed source line. */
  raw: string
}

/** Tokenize a shell line, keeping quoted runs (with spaces) as single tokens. */
function tokenize(line: string): string[] {
  return line.match(/"[^"]*"|'[^']*'|\S+/g) ?? []
}

/**
 * Parse a single shell line into a {@link CliInvocation}, or `undefined` if it
 * is not a `vaultkeeper <command>` invocation (comment, blank, package-manager
 * line, or a bare top-level flag like `vaultkeeper --help`).
 */
function parseInvocation(rawLine: string, lineNo: number): CliInvocation | undefined {
  const line = rawLine.trim()
  if (line === '' || line.startsWith('#')) return undefined

  const tokens = tokenize(line)
  const vkIdx = tokens.indexOf('vaultkeeper')
  if (vkIdx === -1) return undefined

  const args = tokens.slice(vkIdx + 1)
  // The command is the first positional (non-flag) argument. A bare
  // `vaultkeeper --help` has none — skip it (top-level flags are stable).
  const command = args.find((a) => !a.startsWith('-'))
  if (command === undefined) return undefined

  const flags: string[] = []
  for (const arg of args) {
    // Everything after a standalone `--` is the wrapped command, not exec flags.
    if (arg === '--') break
    if (arg.startsWith('-')) {
      const name = arg.split('=')[0]
      if (name !== undefined && name !== '') flags.push(name)
    }
  }
  return { command, flags, line: lineNo, raw: line }
}

/** Extract all `vaultkeeper` CLI invocations from shell fences in `markdown`. */
export function parseReadmeInvocations(markdown: string): CliInvocation[] {
  const out: CliInvocation[] = []
  const lines = markdown.split('\n')
  let inFence = false
  let lang = ''
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? ''
    const fence = /^```(\w*)/.exec(raw.trim())
    if (fence !== null) {
      if (inFence) {
        inFence = false
        lang = ''
      } else {
        inFence = true
        lang = (fence[1] ?? '').toLowerCase()
      }
      continue
    }
    if (!inFence || !SHELL_FENCE_LANGS.has(lang)) continue
    const inv = parseInvocation(raw, i + 1)
    if (inv !== undefined) out.push(inv)
  }
  return out
}

/**
 * Collect the flags a command documents, from the leading flag tokens of each
 * `--help` line (e.g. `  --secret <name>   Description` → `--secret`, and
 * `  -h, --help   ...` → `-h`, `--help`). Prose mentions of a flag mid-sentence
 * are ignored because those lines do not start with `-`.
 */
export function extractHelpFlags(helpText: string): Set<string> {
  const flags = new Set<string>()
  for (const rawLine of helpText.split('\n')) {
    const line = rawLine.trim()
    if (!line.startsWith('-')) continue
    for (const token of line.split(/[\s,]+/)) {
      if (token.startsWith('-')) flags.add(token)
      else break
    }
  }
  return flags
}

/**
 * Parse the subcommand names from the top-level `vaultkeeper --help` output —
 * the indented entries under the `Commands:` heading. This is the source of
 * truth for which commands actually exist, used to catch a README example that
 * references an unknown command.
 */
export function extractCommandNames(topLevelHelp: string): Set<string> {
  const names = new Set<string>()
  let inCommands = false
  for (const rawLine of topLevelHelp.split('\n')) {
    if (!inCommands) {
      if (rawLine.trim() === 'Commands:') inCommands = true
      continue
    }
    if (rawLine.trim() === '') break
    const match = /^\s+([a-z][a-z0-9-]*)\b/.exec(rawLine)
    if (match?.[1] !== undefined) names.add(match[1])
  }
  return names
}

const README_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
  '..',
  'README.md',
)

// Parse the README synchronously at collection time so the per-command drift
// checks below can be registered from the README's own contents. This means a
// newly added example for a new command (with flags) is covered automatically —
// there is no hard-coded command list to fall out of sync.
const INVOCATIONS = parseReadmeInvocations(readFileSync(README_PATH, 'utf8'))
const COMMANDS_WITH_FLAGS = [
  ...new Set(INVOCATIONS.filter((i) => i.flags.length > 0).map((i) => i.command)),
].sort()

describe('README CLI examples do not drift from --help', () => {
  let env: CliTestEnv | undefined

  beforeAll(async () => {
    env = await createCliTestEnv()
  })

  afterAll(async () => {
    // Guard: env may be undefined if createCliTestEnv() threw, in which case
    // calling cleanup() would throw a TypeError and mask the real failure.
    if (env !== undefined) await env.cleanup()
  })

  function requireEnv(): CliTestEnv {
    if (env === undefined) throw new Error('CLI test env was not initialized')
    return env
  }

  it('finds vaultkeeper CLI examples with flags in the README', () => {
    // Guard against a parser that silently matches nothing (which would make the
    // whole drift check vacuously pass by registering zero per-command checks).
    expect(INVOCATIONS.length).toBeGreaterThan(0)
    expect(COMMANDS_WITH_FLAGS).toContain('exec')
  })

  // Coverage guard: every flag-using command in the README is a real top-level
  // command (per `vaultkeeper --help`). Combined with the README-derived
  // registration below, this ensures no example escapes the drift check — a
  // typo'd or removed command surfaces here, and a genuine new command's flags
  // are checked automatically.
  it('only references real CLI commands, each of which gets a drift check', async () => {
    const help = await requireEnv().run(['--help'])
    expect(help.exitCode).toBe(0)
    const realCommands = extractCommandNames(help.stdout)
    expect(realCommands.size).toBeGreaterThan(0)

    const unknown = COMMANDS_WITH_FLAGS.filter((c) => !realCommands.has(c))
    expect(
      unknown,
      `README example(s) reference command(s) not in \`vaultkeeper --help\`: ${unknown.join(', ')}`,
    ).toEqual([])
  })

  // One assertion per command (derived from the README) so a failure names
  // exactly which command drifted.
  for (const command of COMMANDS_WITH_FLAGS) {
    it(`every flag used in \`vaultkeeper ${command}\` README examples is accepted by its --help`, async () => {
      const used = INVOCATIONS.filter((i) => i.command === command)
      const help = await requireEnv().run([command, '--help'])
      expect(help.exitCode, `\`${command} --help\` should exit 0`).toBe(0)
      const known = extractHelpFlags(help.stdout)

      const violations: string[] = []
      for (const inv of used) {
        for (const flag of inv.flags) {
          if (!known.has(flag)) {
            violations.push(
              `README line ${String(inv.line)}: "${inv.raw}" uses ${flag}, ` +
                `which \`vaultkeeper ${command} --help\` does not document`,
            )
          }
        }
      }
      expect(violations, violations.join('\n')).toEqual([])
    })
  }
})

describe('drift detector logic', () => {
  it('extracts the command and flags, stopping at the -- separator', () => {
    const md = [
      '```sh',
      'vaultkeeper exec --secret S --env E --caller C -- run --inner',
      '```',
    ].join('\n')
    const [inv] = parseReadmeInvocations(md)
    expect(inv?.command).toBe('exec')
    // `--inner` belongs to the wrapped command and must be excluded.
    expect(inv?.flags).toEqual(['--secret', '--env', '--caller'])
  })

  it('detects a flag that is not in the help flag set', () => {
    const known = extractHelpFlags('Options:\n  --secret <name>   x\n  --env <VAR>   y\n')
    expect(known.has('--secret')).toBe(true)
    // The historical broken example `exec --token` must be caught.
    expect(known.has('--token')).toBe(false)
  })

  it('extracts subcommand names from the top-level Commands: block', () => {
    const help = [
      'Usage: vaultkeeper <command> [options]',
      '',
      'Commands:',
      '  exec         Run a command with a secret',
      '  dev-mode     Toggle development mode',
      '  rotate-key   Rotate the encryption key',
    ].join('\n')
    const names = extractCommandNames(help)
    expect(names.has('exec')).toBe(true)
    expect(names.has('dev-mode')).toBe(true)
    expect(names.has('rotate-key')).toBe(true)
    // The usage line and heading are not commands.
    expect(names.has('vaultkeeper')).toBe(false)
    expect(names.has('Commands')).toBe(false)
  })

  it('ignores comments, package-manager lines, and non-shell fences', () => {
    const md = [
      '```ts',
      'vaultkeeper exec --token x', // wrong language fence — ignored
      '```',
      '```sh',
      '# vaultkeeper exec --token x', // comment — ignored
      'pnpm add -g @vaultkeeper/cli', // not a vaultkeeper invocation
      'vaultkeeper --help', // bare top-level flag — ignored
      '```',
    ].join('\n')
    expect(parseReadmeInvocations(md)).toEqual([])
  })
})

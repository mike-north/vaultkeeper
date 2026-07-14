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
import * as fs from 'node:fs/promises'
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

const README_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
  '..',
  'README.md',
)

describe('README CLI examples do not drift from --help', () => {
  let env: CliTestEnv
  let invocations: CliInvocation[]
  let commandsWithFlags: string[]

  beforeAll(async () => {
    const markdown = await fs.readFile(README_PATH, 'utf8')
    invocations = parseReadmeInvocations(markdown)
    commandsWithFlags = [
      ...new Set(invocations.filter((i) => i.flags.length > 0).map((i) => i.command)),
    ].sort()
    env = await createCliTestEnv()
  })

  afterAll(async () => {
    await env.cleanup()
  })

  it('finds vaultkeeper CLI examples in the README', () => {
    // Guard against a parser that silently matches nothing (which would make the
    // whole drift check vacuously pass).
    expect(invocations.length).toBeGreaterThan(0)
    expect(commandsWithFlags).toContain('exec')
  })

  it('checks every command that uses flags in a README example', () => {
    // Data-driven registration below depends on this being non-empty.
    expect(commandsWithFlags.length).toBeGreaterThan(0)
  })

  // One assertion per command so a failure names exactly which command drifted.
  for (const command of ['approve', 'delete', 'dev-mode', 'exec', 'store']) {
    it(`every flag used in \`vaultkeeper ${command}\` README examples is accepted by its --help`, async () => {
      const used = invocations.filter((i) => i.command === command)
      // Only assert for commands actually exemplified with flags in the README.
      if (used.length === 0 || used.every((i) => i.flags.length === 0)) return

      const help = await env.run([command, '--help'])
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

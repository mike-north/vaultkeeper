/**
 * Nearest-command suggestion for unknown subcommands ("did you mean …?").
 *
 * Mirrors the affordance npm/git/cargo provide: a typo like `doctro` should
 * surface `doctor` rather than a bare "unknown command" with no next step.
 *
 * @internal
 */

/**
 * The canonical list of top-level subcommands, in the order they appear in
 * `--help`. Kept alongside the `bin.ts` dispatch switch it is derived from —
 * update both together when a command is added or removed.
 */
export const KNOWN_COMMANDS: readonly string[] = [
  'exec',
  'doctor',
  'approve',
  'dev-mode',
  'store',
  'delete',
  'key',
  'sign',
  'verify',
  'config',
  'rotate-key',
  'revoke-key',
]

/**
 * Levenshtein edit distance between two strings (insertions, deletions, and
 * substitutions each cost 1). Used to rank candidate commands by closeness to
 * the user's typo.
 */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0
  if (a.length === 0) return b.length
  if (b.length === 0) return a.length

  // Single-row dynamic-programming table; `prev[j]` holds the distance for the
  // previous source-prefix length, rebuilt row by row.
  let prev: number[] = []
  for (let j = 0; j <= b.length; j++) prev[j] = j

  for (let i = 1; i <= a.length; i++) {
    const curr: number[] = [i]
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      const deletion = (prev[j] ?? 0) + 1
      const insertion = (curr[j - 1] ?? 0) + 1
      const substitution = (prev[j - 1] ?? 0) + cost
      curr[j] = Math.min(deletion, insertion, substitution)
    }
    prev = curr
  }
  return prev[b.length] ?? 0
}

/**
 * Return the known command closest to `input`, or `undefined` when nothing is
 * close enough to be a helpful suggestion.
 *
 * The threshold scales with the input length (a longer word tolerates more
 * typos) but is capped so wildly different words never produce a misleading
 * suggestion — `doctro` → `doctor`, but `xyz` → nothing.
 */
export function suggestCommand(
  input: string,
  commands: readonly string[] = KNOWN_COMMANDS,
): string | undefined {
  if (input === '') return undefined

  // Tolerate up to a third of the input length in edits, but never more than 3.
  const maxDistance = Math.min(3, Math.floor(input.length / 3) + 1)

  let best: string | undefined
  let bestDistance = Number.POSITIVE_INFINITY
  for (const command of commands) {
    const distance = levenshtein(input, command)
    if (distance < bestDistance) {
      best = command
      bestDistance = distance
    }
  }

  return bestDistance <= maxDistance ? best : undefined
}

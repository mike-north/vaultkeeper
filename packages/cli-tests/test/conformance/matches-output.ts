/**
 * Shared output-matcher logic for the conformance test runners.
 *
 * Both `run-conformance.test.ts` (native Rust CLI conformance) and
 * `stub-tool-axes.test.ts` (StubTool axis conformance) assert against the
 * same `OutputMatcher` shape exported by the `vaultkeeper-conformance` Rust
 * crate, so the matching logic — including the `JsonContains` case and the
 * Rust `(?s)` inline-flag -> JS `s` (dotall) flag translation for `Regex` —
 * must behave identically in both. Keeping a single implementation here
 * means a corpus case written against one axis (e.g. a `(?s)` regex or a
 * `JsonContains` matcher) behaves the same regardless of which runner
 * exercises it.
 *
 * @see crates/vaultkeeper-conformance/src/lib.rs — `OutputMatcher` definition
 * @see crates/vaultkeeper-conformance/src/lib.rs — `matches_output` (Rust counterpart)
 */

export interface OutputMatcher {
  type: 'Any' | 'Exact' | 'Contains' | 'Regex' | 'JsonContains'
  value?: string | Record<string, unknown>
}

function matcherValueAsString(matcher: OutputMatcher): string {
  if (typeof matcher.value === 'string') return matcher.value
  return ''
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function jsonContains(haystack: unknown, needle: unknown): boolean {
  if (isRecord(haystack) && isRecord(needle)) {
    return Object.entries(needle).every(([k, v]) => k in haystack && jsonContains(haystack[k], v))
  }
  if (Array.isArray(haystack) && Array.isArray(needle)) {
    return needle.every((nv: unknown) => haystack.some((hv: unknown) => jsonContains(hv, nv)))
  }
  return haystack === needle
}

export function matchesOutput(matcher: OutputMatcher, output: string): boolean {
  switch (matcher.type) {
    case 'Any':
      return true
    case 'Exact':
      return output.trim() === matcherValueAsString(matcher).trim()
    case 'Contains':
      return output.includes(matcherValueAsString(matcher))
    case 'Regex': {
      let pattern = matcherValueAsString(matcher)
      let flags = ''
      // Translate Rust inline (?s) flag to JS 's' flag (dotall mode)
      if (pattern.startsWith('(?s)')) {
        pattern = pattern.slice(4)
        flags = 's'
      }
      return new RegExp(pattern, flags).test(output)
    }
    case 'JsonContains': {
      try {
        const parsed: unknown = JSON.parse(output)
        return jsonContains(parsed, matcher.value)
      } catch {
        return false
      }
    }
    default:
      return false
  }
}

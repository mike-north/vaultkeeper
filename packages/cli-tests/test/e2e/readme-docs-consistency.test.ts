/**
 * Docs consistency guard for the root README, extending the drift-check family
 * started by the README/CLI drift check (#62). Catches regressions from
 * https://github.com/mike-north/vaultkeeper/issues/102:
 *
 * 1. An "access pattern" named in prose (e.g. in the "Which package should I
 *    use?" delegated-access-patterns list) that isn't a real `VaultKeeper`
 *    method or a real `vaultkeeper` package export — a phantom reference like
 *    `createSecretAccessor`, which is not exported from `src/index.ts`.
 * 2. A default-backend statement in the package-choice summary that
 *    contradicts the quick-start config note — both must agree that a
 *    zero-config `vaultkeeper`/`VaultKeeper.init()` resolves to the safe
 *    `file` backend (the native credential store is opt-in only).
 * 3. A trust-tier description that overclaims a Sigstore-transparency-log or
 *    package-registry-signature verification model. Per
 *    `packages/vaultkeeper/src/identity/trust.ts`, the real mechanism is
 *    TOFU-manifest hash checking: a caller's hash is "approved" (found in the
 *    trust manifest), "not yet approved" (first encounter), or "mismatch"
 *    (changed since approval). The Sigstore integration point is a stub that
 *    always falls through, and "tier 2" is not a registry check — it is the
 *    same trust-manifest lookup as tier 3.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/102
 * @see https://github.com/mike-north/vaultkeeper/issues/62
 */
import { readFileSync } from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..')
const README = readFileSync(path.join(ROOT, 'README.md'), 'utf8')
const VAULT_TS = readFileSync(path.join(ROOT, 'packages/vaultkeeper/src/vault.ts'), 'utf8')
const INDEX_TS = readFileSync(path.join(ROOT, 'packages/vaultkeeper/src/index.ts'), 'utf8')

/** Public (non-private, non-indented-deeper) instance method names on the `VaultKeeper` class. */
export function extractVaultKeeperMethods(source: string): Set<string> {
  const names = new Set<string>()
  const re = /^\s{2}(?:async\s+)?([a-zA-Z][a-zA-Z0-9]*)\s*\(/gm
  let m: RegExpExecArray | null
  while ((m = re.exec(source)) !== null) {
    const name = m[1]
    if (name !== undefined) names.add(name)
  }
  return names
}

/** Named values/types re-exported from `src/index.ts` (the public API surface). */
export function extractIndexExports(source: string): Set<string> {
  const names = new Set<string>()
  const re = /export\s+(?:type\s+)?\{([^}]*)\}/g
  let m: RegExpExecArray | null
  while ((m = re.exec(source)) !== null) {
    for (const raw of (m[1] ?? '').split(',')) {
      const name = raw
        .trim()
        .split(/\s+as\s+/)[0]
        ?.trim()
      if (name !== undefined && name !== '') names.add(name)
    }
  }
  return names
}

describe('README access-pattern names resolve to real exports', () => {
  const methods = extractVaultKeeperMethods(VAULT_TS)
  const publicExports = extractIndexExports(INDEX_TS)

  it('parses the known real VaultKeeper access-pattern methods', () => {
    // Guard against a parser regression that would make this whole check
    // vacuously pass by finding zero methods.
    expect(methods.has('fetch')).toBe(true)
    expect(methods.has('exec')).toBe(true)
    expect(methods.has('getSecret')).toBe(true)
  })

  it('never names the removed createSecretAccessor as an access pattern (issue #102)', () => {
    expect(README.includes('createSecretAccessor')).toBe(false)
  })

  it('the "Which package should I use?" delegated-access-patterns list names only real VaultKeeper methods', () => {
    // Match the backtick-delimited items themselves (`fetch`, `exec`,
    // `getSecret()`, ...) rather than stopping at the segment's first `)` —
    // a naive `\(([^)]*)\)` capture stops inside `getSecret()`'s own parens,
    // truncating the list before it reaches the real closing paren.
    const match = /delegated access patterns \(((?:`[^`]+`,?\s*)+)\)/.exec(README)
    expect(match, 'expected to find the delegated access patterns list in README.md').not.toBeNull()

    const names = [...(match?.[1] ?? '').matchAll(/`([^`]+)`/g)]
      .map(([, name]) => name?.replace(/\(\)$/, '').trim())
      .filter((s): s is string => s !== undefined && s.length > 0)
    expect(names.length).toBeGreaterThan(0)

    const unknown = names.filter((n) => !methods.has(n) && !publicExports.has(n))
    expect(
      unknown,
      `README names access pattern(s) with no matching VaultKeeper method or public export: ${unknown.join(', ')}`,
    ).toEqual([])
  })
})

describe('README default-backend statement is internally consistent (issue #102)', () => {
  it('the package-choice summary and the quick-start config note agree that a zero-config default resolves to the file backend', () => {
    const whichPackageBullet = /- \*\*`vaultkeeper`\*\*.*?(?=\n- \*\*)/s.exec(README)?.[0]
    expect(
      whichPackageBullet,
      'expected to find the `vaultkeeper` bullet in "Which package should I use?"',
    ).toBeDefined()
    expect(whichPackageBullet).toMatch(/no config file present it uses the safe `file` backend/)

    // README.md has more than one [!NOTE] block; anchor on the one that
    // discusses `VaultKeeper.init()` specifically (the TypeScript quick start).
    const configNote = [...README.matchAll(/> \[!NOTE\][\s\S]*?(?=\n\n)/g)].find((block) =>
      block[0].includes('VaultKeeper.init()'),
    )?.[0]
    expect(
      configNote,
      'expected to find the TypeScript quick-start config [!NOTE] block',
    ).toBeDefined()
    expect(configNote).toMatch(/resolves to the safe, portable `file` backend/)

    // Neither statement's zero-config-default clause (up to the first
    // sentence boundary) may claim the platform-native store as the resolved
    // default — later "opt into keychain/dpapi" language in the same
    // sentence is expected and must not trip this check.
    const bulletDefaultClause =
      /no config file present it [^.;]*/i.exec(whichPackageBullet ?? '')?.[0] ?? ''
    expect(bulletDefaultClause).not.toMatch(/keychain|dpapi|native/i)

    const noteDefaultClause = /resolves to [^.;]*/i.exec(configNote ?? '')?.[0] ?? ''
    expect(noteDefaultClause).not.toMatch(/keychain|dpapi|native credential store/i)
  })

  it('no [!WARNING] block claims a bare zero-config init targets the real/native credential store', () => {
    // Narrowly targets the specific stale claim this issue is about (see the
    // pre-#108 text: "a bare `VaultKeeper.init()` ... targets your **real OS
    // credential store**"), not the mere presence of a [!WARNING] block —
    // an unrelated warning added later must not trip this check.
    const badClaim =
      /bare\s+(`vaultkeeper config init`|`VaultKeeper\.init\(\)`)[\s\S]{0,200}?(targets?|resolves? to)[\s\S]{0,80}?(real|platform-native)[\s\S]{0,40}?(credential store|keychain|dpapi)/i
    const warningBlocks = [...README.matchAll(/> \[!WARNING\][\s\S]*?(?=\n\n)/g)].map((m) => m[0])
    for (const block of warningBlocks) {
      expect(
        block,
        `[!WARNING] block reintroduces the stale claim that a zero-config init targets the native store:\n${block}`,
      ).not.toMatch(badClaim)
    }
  })
})

describe('README trust-tier description matches the real TOFU-manifest mechanism (issue #102)', () => {
  it('does not claim tier 1/2 are active Sigstore or registry-signature verification', () => {
    // These exact phrasings previously appeared as table cells claiming an
    // active verification mechanism; the caveat prose intentionally *names*
    // Sigstore and registry checks while explaining they don't happen, so
    // this asserts the old table-row phrasing specifically, not the words.
    expect(README).not.toMatch(/Sigstore transparency log/i)
    expect(README).not.toMatch(/\|\s*Registry signature\s*\|/i)
    expect(README).not.toMatch(/\|\s*Intended method\s*\|/i)
  })

  it('describes the actual TOFU (trust-manifest hash) model with its three real outcomes', () => {
    const trustSection = /## Trust tiers[\s\S]*?(?=\n## )/.exec(README)?.[0]
    expect(trustSection, 'expected to find the "## Trust tiers" section in README.md').toBeDefined()
    expect(trustSection).toMatch(/TOFU/)
    expect(trustSection).toMatch(/Not yet approved/i)
    expect(trustSection).toMatch(/Approved/)
    expect(trustSection).toMatch(/Mismatch/i)
    // The honest caveat: Sigstore is a non-functional stub, and "tier 2" is
    // not a registry check — both must stay documented so this doesn't drift
    // back to an overclaim.
    expect(trustSection).toMatch(/stub/i)
    expect(trustSection).toMatch(/no executable is verified via Sigstore or any package registry/i)
  })
})

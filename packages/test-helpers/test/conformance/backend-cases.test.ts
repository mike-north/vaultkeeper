/**
 * Conformance fidelity gate for the `InMemoryBackend` test double (issue #312).
 *
 * Runs the exact same data-driven `BackendConformanceCase` corpus exported
 * from `vaultkeeper-conformance` (Rust crate) against the TS
 * `InMemoryBackend` double, mirroring the existing JS conformance-runner
 * pattern in `packages/cli-tests/test/conformance/run-conformance.test.ts`
 * (load cases exported to JSON, run each against the implementation under
 * test, aggregate failures). This corpus is scoped to backend-level
 * behavior — store/retrieve/delete/exists/list/sign/capability — applicable
 * to any `SecretBackend` implementation, not the CLI-argv-only cases in
 * `crates/vaultkeeper-conformance/src/lib.rs` (see that corpus's
 * `backend_cases` module doc for why those two corpora are separate).
 *
 * The identical corpus also runs against the Rust core `InMemoryBackend` in
 * `crates/vaultkeeper-core/tests/backend_conformance.rs`, proving
 * cross-language parity (issue #312 AC4).
 *
 * @see crates/vaultkeeper-conformance/src/backend_cases.rs — case definitions
 * @see crates/vaultkeeper-core/tests/backend_conformance.rs — Rust-side runner
 */

import * as crypto from 'node:crypto'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'
import { InMemoryBackend } from '../../src/index.js'

// ─── Types mirroring the Rust BackendConformanceCase / BackendStep ────────

type BackendStep =
  | { op: 'store'; id: string; secret: string }
  | { op: 'expectRetrieve'; id: string; secret: string }
  | { op: 'expectRetrieveNotFound'; id: string }
  | { op: 'delete'; id: string }
  | { op: 'expectDeleteNotFound'; id: string }
  | { op: 'expectExists'; id: string; exists: boolean }
  | { op: 'expectListContains'; ids: string[] }
  | { op: 'expectListDoesNotContain'; ids: string[] }
  | { op: 'generateSigningKey'; id: string }
  | { op: 'expectGenerateSigningKeyAlreadyExists'; id: string }
  | { op: 'expectSignRoundTrips'; id: string; message: string }
  | { op: 'expectGetPublicKeyNotFound'; id: string }
  | { op: 'expectSignNotFound'; id: string }
  | { op: 'expectPresencePerUse'; value: boolean }

interface BackendConformanceCase {
  name: string
  steps: BackendStep[]
}

// ─── Load cases ─────────────────────────────────────────────────────────

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0
  )
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function isBackendStep(value: unknown): value is BackendStep {
  if (!isPlainObject(value) || typeof value.op !== 'string') {
    return false
  }
  switch (value.op) {
    case 'store':
    case 'expectRetrieve':
      return typeof value.id === 'string' && typeof value.secret === 'string'
    case 'expectRetrieveNotFound':
    case 'delete':
    case 'expectDeleteNotFound':
    case 'generateSigningKey':
    case 'expectGenerateSigningKeyAlreadyExists':
    case 'expectGetPublicKeyNotFound':
    case 'expectSignNotFound':
      return typeof value.id === 'string'
    case 'expectExists':
      return typeof value.id === 'string' && typeof value.exists === 'boolean'
    case 'expectListContains':
    case 'expectListDoesNotContain':
      return isStringArray(value.ids)
    case 'expectSignRoundTrips':
      return typeof value.id === 'string' && typeof value.message === 'string'
    case 'expectPresencePerUse':
      return typeof value.value === 'boolean'
    default:
      return false
  }
}

function isBackendConformanceCase(value: unknown): value is BackendConformanceCase {
  return (
    isPlainObject(value) &&
    typeof value.name === 'string' &&
    Array.isArray(value.steps) &&
    value.steps.every(isBackendStep)
  )
}

function isBackendConformanceCaseArray(value: unknown): value is BackendConformanceCase[] {
  return Array.isArray(value) && value.every(isBackendConformanceCase)
}

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const casesPath = path.join(__dirname, 'backend-cases.json')
const parsedCases: unknown = JSON.parse(await fs.readFile(casesPath, 'utf8'))
if (!isBackendConformanceCaseArray(parsedCases)) {
  throw new Error(`${casesPath} does not contain a valid BackendConformanceCase[] shape`)
}
const cases: BackendConformanceCase[] = parsedCases

// ─── Runner ─────────────────────────────────────────────────────────────

/**
 * Run a single {@link BackendConformanceCase} against `backend`, throwing a
 * descriptive `Error` on the first failing step. Exported (module-private,
 * but reachable from this file's own drift-detection test below) so the
 * suite and the drift-proof test share one implementation rather than two
 * hand-duplicated copies.
 */
async function runCase(backend: InMemoryBackend, testCase: BackendConformanceCase): Promise<void> {
  for (const step of testCase.steps) {
    switch (step.op) {
      case 'store':
        await backend.store(step.id, step.secret)
        break
      case 'expectRetrieve': {
        const got = await backend.retrieve(step.id)
        if (got !== step.secret) {
          throw new Error(
            `retrieve(${step.id}) returned ${JSON.stringify(got)}, expected ${JSON.stringify(step.secret)}`,
          )
        }
        break
      }
      case 'expectRetrieveNotFound': {
        await expectRejectsWithName(
          backend.retrieve(step.id),
          'SecretNotFoundError',
          step.op,
          step.id,
        )
        break
      }
      case 'delete':
        await backend.delete(step.id)
        break
      case 'expectDeleteNotFound': {
        await expectRejectsWithName(
          backend.delete(step.id),
          'SecretNotFoundError',
          step.op,
          step.id,
        )
        break
      }
      case 'expectExists': {
        const got = await backend.exists(step.id)
        if (got !== step.exists) {
          throw new Error(
            `exists(${step.id}) returned ${String(got)}, expected ${String(step.exists)}`,
          )
        }
        break
      }
      case 'expectListContains': {
        const listed = await backend.list()
        for (const id of step.ids) {
          if (!listed.includes(id)) {
            throw new Error(`list() ${JSON.stringify(listed)} does not contain ${id}`)
          }
        }
        break
      }
      case 'expectListDoesNotContain': {
        const listed = await backend.list()
        for (const id of step.ids) {
          if (listed.includes(id)) {
            throw new Error(`list() ${JSON.stringify(listed)} unexpectedly contains ${id}`)
          }
        }
        break
      }
      case 'generateSigningKey':
        await backend.generateSigningKey(step.id, 'EdDSA')
        break
      case 'expectGenerateSigningKeyAlreadyExists': {
        await expectRejectsWithName(
          backend.generateSigningKey(step.id, 'EdDSA'),
          'SigningKeyAlreadyExistsError',
          step.op,
          step.id,
        )
        break
      }
      case 'expectSignRoundTrips': {
        const publicKey = await backend.getPublicKey(step.id)
        const message = Buffer.from(step.message, 'utf8')
        const signature = await backend.signWithKey(step.id, message)
        const verifyingKey = crypto.createPublicKey(publicKey.publicKeyPem)
        if (!crypto.verify(null, message, verifyingKey, signature)) {
          throw new Error(
            `signWithKey(${step.id}) signature did not verify against its own public key`,
          )
        }
        const tampered = Buffer.from('a tampered payload', 'utf8')
        if (crypto.verify(null, tampered, verifyingKey, signature)) {
          throw new Error(`signWithKey(${step.id}) signature verified against a tampered payload`)
        }
        break
      }
      case 'expectGetPublicKeyNotFound': {
        await expectRejectsWithName(
          backend.getPublicKey(step.id),
          'SigningKeyNotFoundError',
          step.op,
          step.id,
        )
        break
      }
      case 'expectSignNotFound': {
        await expectRejectsWithName(
          backend.signWithKey(step.id, Buffer.from('data')),
          'SigningKeyNotFoundError',
          step.op,
          step.id,
        )
        break
      }
      case 'expectPresencePerUse': {
        const caps = await backend.getCapabilities()
        if (caps.presencePerUse !== step.value) {
          throw new Error(
            `getCapabilities().presencePerUse was ${String(caps.presencePerUse)}, expected ${String(step.value)}`,
          )
        }
        break
      }
      default: {
        const unhandled: never = step
        throw new Error(`unhandled BackendStep kind: ${JSON.stringify(unhandled)}`)
      }
    }
  }
}

/** Assert `promise` rejects with an error whose `name` (the project's stable discriminator) is `expectedName`. */
async function expectRejectsWithName(
  promise: Promise<unknown>,
  expectedName: string,
  op: string,
  id: string,
): Promise<void> {
  let didThrow = false
  let threw: unknown
  try {
    await promise
  } catch (err) {
    didThrow = true
    threw = err
  }
  if (!didThrow) {
    throw new Error(`${op}(${id}) expected to reject with ${expectedName}, but it resolved`)
  }
  const actualName = threw instanceof Error ? threw.name : typeof threw
  const actualMessage = threw instanceof Error ? threw.message : JSON.stringify(threw)
  if (actualName !== expectedName) {
    throw new Error(
      `${op}(${id}) expected to reject with ${expectedName}, got ${actualName}: ${actualMessage}`,
    )
  }
}

// ─── Test suite (AC1) ───────────────────────────────────────────────────

describe('InMemoryBackend conformance fidelity gate', () => {
  it.each(cases.map((c): [string, BackendConformanceCase] => [c.name, c]))(
    '%s',
    async (_name, testCase) => {
      const backend = new InMemoryBackend()
      await expect(runCase(backend, testCase)).resolves.toBeUndefined()
    },
  )
})

// ─── Drift-detection proof (AC2) ─────────────────────────────────────────
//
// Proves the gate actually detects drift rather than passing vacuously: a
// deliberately mutated case (wrong expected secret value) must cause the
// runner to fail. This does NOT ship a broken gate — the mutated case only
// exists inside this one test and is never added to `cases`/the suite above.

describe('InMemoryBackend conformance fidelity gate — drift detection (AC2)', () => {
  it('fails when a case expectation the double does not meet is introduced', async () => {
    const original = cases.find((c) => c.name === 'store then retrieve returns the same secret')
    if (original === undefined) {
      throw new Error("fixture case 'store then retrieve returns the same secret' must exist")
    }

    // Deliberately diverge the case from what InMemoryBackend actually does:
    // claim the stored secret is a different value than what was stored.
    const mutated: BackendConformanceCase = {
      name: original.name,
      steps: original.steps.map((step) =>
        step.op === 'expectRetrieve' ? { ...step, secret: `${step.secret}-drifted` } : step,
      ),
    }

    const backend = new InMemoryBackend()
    await expect(runCase(backend, mutated)).rejects.toThrow(/expected "conformance-secret-drifted"/)
  })

  it('fails when a not-found expectation the double does not meet is introduced', async () => {
    const backend = new InMemoryBackend()
    // The double correctly resolves retrieve() for a stored id — asserting
    // it must instead reject with SecretNotFoundError is the drift.
    await backend.store('present', 'value')
    const mutated: BackendConformanceCase = {
      name: 'drift: retrieve of a present id incorrectly asserted not-found',
      steps: [{ op: 'expectRetrieveNotFound', id: 'present' }],
    }
    await expect(runCase(backend, mutated)).rejects.toThrow(
      /expected to reject with SecretNotFoundError/,
    )
  })
})

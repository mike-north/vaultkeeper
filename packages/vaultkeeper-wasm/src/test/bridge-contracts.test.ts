/**
 * Bridge-contract tests for issue #239 (Phase 0 bridge contracts):
 * `HostPlatform::exec` env/cwd options, `HostPlatform::http_fetch`,
 * `HostPlatform::prompt_approval`, and the `JsSecretBackend` scaffold.
 *
 * Uses node:test (not vitest) since this package compiles with plain tsc.
 */

/* eslint-disable @typescript-eslint/no-floating-promises -- node:test it() returns Promise but is not meant to be awaited inside describe() */
/* eslint-disable n/no-unsupported-features/node-builtins -- test.describe is stable in our CI Node version */

import { describe, it } from 'node:test'
import * as assert from 'node:assert/strict'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { createNodeHost } from '../node-host.js'
import { mapWasmError, FetchError, NotCapableError, VaultError } from '../errors.js'
import type { HostSecretBackend } from '../types.js'

/** Loose shape of a value thrown across the WASM boundary (see `../errors.ts`). */
interface BridgeErrorShape {
  vaultErrorCode: string
  message: string
}

function isBridgeErrorShape(value: unknown): value is BridgeErrorShape {
  if (typeof value !== 'object' || value === null) return false
  const record: Record<string, unknown> = { ...value }
  return typeof record.vaultErrorCode === 'string' && typeof record.message === 'string'
}

/**
 * Narrows `net.Server#address()`'s `string | AddressInfo | null` return to
 * `AddressInfo` without an `as` cast (forbidden repo-wide —
 * `consistent-type-assertions: never`).
 */
function assertAddressInfo(value: string | AddressInfo | null): asserts value is AddressInfo {
  assert.ok(
    typeof value === 'object' && value !== null,
    'expected server.address() to return AddressInfo, not a string or null (pipe/UNIX socket?)',
  )
}

/** The `{ status, headers, body }` shape `__testHttpFetch` resolves with. */
interface DiagnosticHttpResponse {
  status: number
  headers: Record<string, string>
  body: Uint8Array
}

/** The `{ stdout, stderr, exitCode }` shape `__testExec` resolves with. */
interface DiagnosticExecOutput {
  stdout: Uint8Array
  stderr: Uint8Array
  exitCode: number
}

/** Narrows `__testHttpFetch`'s `unknown` result without an `as` cast. */
function assertDiagnosticHttpResponse(value: unknown): asserts value is DiagnosticHttpResponse {
  assert.ok(
    typeof value === 'object' && value !== null,
    '__testHttpFetch must resolve to an object',
  )
  const record: Record<string, unknown> = { ...value }
  assert.ok(typeof record.status === 'number', 'response.status must be a number')
  assert.ok(
    typeof record.headers === 'object' && record.headers !== null,
    'response.headers must be an object',
  )
  assert.ok(record.body instanceof Uint8Array, 'response.body must be a Uint8Array')
}

/** Narrows `__testExec`'s `unknown` result without an `as` cast. */
function assertDiagnosticExecOutput(value: unknown): asserts value is DiagnosticExecOutput {
  assert.ok(typeof value === 'object' && value !== null, '__testExec must resolve to an object')
  const record: Record<string, unknown> = { ...value }
  assert.ok(record.stdout instanceof Uint8Array, 'result.stdout must be a Uint8Array')
  assert.ok(record.stderr instanceof Uint8Array, 'result.stderr must be a Uint8Array')
  assert.ok(typeof record.exitCode === 'number', 'result.exitCode must be a number')
}

/**
 * The minimal host shape `JsHostPlatform::new` requires (`platform()`,
 * `configDir()`), plus whichever bridge method under test. Diagnostic-only
 * exports (`__testHttpFetch`, `__testPromptApproval`,
 * `__testJsSecretBackend*`) construct the real Rust-side bridge the same way
 * a genuine `WasmVaultKeeper` host is constructed, so every mock here must
 * satisfy this base contract even though the diagnostic export under test
 * only exercises one method of it.
 */
interface MinimalHost {
  platform(): string
  configDir(): string
}

function baseHost(): MinimalHost {
  return {
    platform: () => 'linux',
    configDir: () => '/tmp/vk-bridge-test',
  }
}

interface DiagnosticBindings {
  __testExec: (host: unknown, cmd: string, args: string[]) => Promise<unknown>
  __testHttpFetch: (host: unknown, request: unknown) => Promise<unknown>
  __testPromptApproval: (host: unknown, action: string, detail: string) => Promise<boolean>
  __testJsSecretBackendMeta: (host: unknown) => unknown
  __testJsSecretBackendIsAvailable: (host: unknown) => Promise<boolean>
  __testJsSecretBackendStore: (host: unknown, id: string, secret: string) => Promise<void>
  __testJsSecretBackendRetrieve: (host: unknown, id: string) => Promise<string>
  __testJsSecretBackendDelete: (host: unknown, id: string) => Promise<void>
  __testJsSecretBackendExists: (host: unknown, id: string) => Promise<boolean>
  __testJsSecretBackendList: (host: unknown) => Promise<string[]>
}

async function loadDiagnosticBindings(): Promise<DiagnosticBindings> {
  // Diagnostic-only exports, deliberately not re-exported from ../index.ts —
  // imported directly from the raw wasm-bindgen glue, mirroring
  // error-parity.test.ts.
  return import('../../wasm/vaultkeeper_wasm.js')
}

// ---------------------------------------------------------------------------
// AC1: exec gains { stdin?, env?, cwd? } options
// ---------------------------------------------------------------------------

describe('createNodeHost().exec — env/cwd options (issue #239 AC1)', () => {
  it('omitting options preserves pre-#239 behavior (no stdin, inherited env/cwd)', async () => {
    const host = createNodeHost('/tmp/vk-bridge-test-configdir')
    const result = await host.exec('node', ['-e', 'process.stdout.write("hello")'])
    assert.equal(result.exitCode, 0)
    assert.equal(Buffer.from(result.stdout).toString(), 'hello')
  })

  it('env is merged on top of the inherited environment, not a replacement', async () => {
    const host = createNodeHost('/tmp/vk-bridge-test-configdir')
    const result = await host.exec(
      'node',
      ['-e', 'process.stdout.write(process.env.VK_BRIDGE_TEST_VAR ?? "")'],
      { env: { VK_BRIDGE_TEST_VAR: 'issue-239' } },
    )
    assert.equal(result.exitCode, 0)
    assert.equal(Buffer.from(result.stdout).toString(), 'issue-239')
    // The inherited PATH must still be present — env is additive, not a wholesale replacement.
    const pathCheck = await host.exec(
      'node',
      ['-e', 'process.stdout.write(process.env.PATH ?? "")'],
      {
        env: { VK_BRIDGE_TEST_VAR: 'issue-239' },
      },
    )
    assert.ok(Buffer.from(pathCheck.stdout).toString().length > 0, 'PATH must still be inherited')
  })

  it('cwd changes the child process working directory', async () => {
    const host = createNodeHost('/tmp/vk-bridge-test-configdir')
    const result = await host.exec('node', ['-e', 'process.stdout.write(process.cwd())'], {
      cwd: '/tmp',
    })
    assert.equal(result.exitCode, 0)
    // Resolve symlinks (macOS /tmp -> /private/tmp) rather than assert exact equality.
    const { realpathSync } = await import('node:fs')
    assert.equal(realpathSync(Buffer.from(result.stdout).toString()), realpathSync('/tmp'))
  })

  it('stdin still works when passed inside the options object', async () => {
    const host = createNodeHost('/tmp/vk-bridge-test-configdir')
    const result = await host.exec(
      'node',
      ['-e', 'process.stdin.on("data", (d) => process.stdout.write(d))'],
      { stdin: new TextEncoder().encode('piped-in') },
    )
    assert.equal(result.exitCode, 0)
    assert.equal(Buffer.from(result.stdout).toString(), 'piped-in')
  })
})

describe('__testExec — rejects malformed exec() result shapes', () => {
  async function expectExecError(result: unknown): Promise<void> {
    const bindings = await loadDiagnosticBindings()
    const host = { ...baseHost(), exec: () => Promise.resolve(result) }
    await assert.rejects(
      () => bindings.__testExec(host, 'node', []),
      (thrown: unknown) => {
        assert.ok(isBridgeErrorShape(thrown))
        const err = mapWasmError(thrown)
        assert.ok(err instanceof VaultError, `expected VaultError, got ${err.constructor.name}`)
        return true
      },
    )
  }

  it('rejects a missing stdout instead of silently producing empty output', async () => {
    await expectExecError({ stderr: new Uint8Array(), exitCode: 0 })
  })

  it('rejects an undefined stdout instead of silently producing empty output', async () => {
    await expectExecError({ stdout: undefined, stderr: new Uint8Array(), exitCode: 0 })
  })

  it('rejects a non-Uint8Array stdout (e.g. a plain number) instead of coercing it', async () => {
    await expectExecError({ stdout: 4, stderr: new Uint8Array(), exitCode: 0 })
  })

  it('rejects a non-Uint8Array stderr (e.g. a plain string) instead of coercing it', async () => {
    await expectExecError({ stdout: new Uint8Array(), stderr: 'not-bytes', exitCode: 0 })
  })

  it('still accepts a well-formed result (control case)', async () => {
    const bindings = await loadDiagnosticBindings()
    const host = {
      ...baseHost(),
      exec: () =>
        Promise.resolve({
          stdout: new Uint8Array([1, 2, 3]),
          stderr: new Uint8Array([4, 5]),
          exitCode: 0,
        }),
    }
    const result = await bindings.__testExec(host, 'node', [])
    assertDiagnosticExecOutput(result)
    assert.deepEqual([...result.stdout], [1, 2, 3])
    assert.deepEqual([...result.stderr], [4, 5])
    assert.equal(result.exitCode, 0)
  })
})

// ---------------------------------------------------------------------------
// AC2: http_fetch primitive
// ---------------------------------------------------------------------------

describe('createNodeHost().httpFetch (issue #239 AC2)', () => {
  it('round-trips a real HTTP request through the global fetch bridge', async () => {
    const server = createServer((req, res) => {
      res.setHeader('x-test-header', 'yes')
      res.statusCode = 201
      res.end(`method=${req.method ?? ''}`)
    })
    await new Promise<void>((resolve) => server.listen(0, resolve))
    const address = server.address()
    assertAddressInfo(address)
    const { port } = address

    try {
      const host = createNodeHost('/tmp/vk-bridge-test-configdir')
      const response = await host.httpFetch({
        method: 'POST',
        url: `http://127.0.0.1:${String(port)}/`,
        headers: {},
      })
      assert.equal(response.status, 201)
      assert.equal(response.headers['x-test-header'], 'yes')
      assert.equal(Buffer.from(response.body).toString(), 'method=POST')
    } finally {
      server.close()
    }
  })

  it('sends the request body', async () => {
    const chunks: Buffer[] = []
    const server = createServer((req, res) => {
      req.on('data', (chunk: Buffer) => chunks.push(chunk))
      req.on('end', () => {
        res.end('ok')
      })
    })
    await new Promise<void>((resolve) => server.listen(0, resolve))
    const address = server.address()
    assertAddressInfo(address)
    const { port } = address

    try {
      const host = createNodeHost('/tmp/vk-bridge-test-configdir')
      await host.httpFetch({
        method: 'PUT',
        url: `http://127.0.0.1:${String(port)}/`,
        headers: {},
        body: new TextEncoder().encode('request-body'),
      })
      assert.equal(Buffer.concat(chunks).toString(), 'request-body')
    } finally {
      server.close()
    }
  })
})

describe('__testHttpFetch — JsHostPlatform::http_fetch bridge (issue #239 AC2)', () => {
  it('forwards the request and parses a well-formed response', async () => {
    const bindings = await loadDiagnosticBindings()
    const host = {
      ...baseHost(),
      httpFetch: (request: { method: string; url: string; headers: Record<string, string> }) =>
        Promise.resolve({
          status: 200,
          headers: { 'x-echo-method': request.method },
          body: new TextEncoder().encode(`echo:${request.url}`),
        }),
    }
    const result = await bindings.__testHttpFetch(host, {
      method: 'GET',
      url: 'https://example.test/resource',
      headers: {},
    })
    assertDiagnosticHttpResponse(result)
    const response = result
    assert.equal(response.status, 200)
    assert.equal(response.headers['x-echo-method'], 'GET')
    assert.equal(Buffer.from(response.body).toString(), 'echo:https://example.test/resource')
  })

  it('a rejecting httpFetch surfaces as a typed FetchError carrying the request url', async () => {
    const bindings = await loadDiagnosticBindings()
    const host = {
      ...baseHost(),
      httpFetch: () => Promise.reject(new Error('network unreachable')),
    }
    await assert.rejects(
      () =>
        bindings.__testHttpFetch(host, {
          method: 'GET',
          url: 'https://example.test/x',
          headers: {},
        }),
      (thrown: unknown) => {
        assert.ok(isBridgeErrorShape(thrown))
        const err = mapWasmError(thrown)
        assert.ok(err instanceof FetchError, `expected FetchError, got ${err.constructor.name}`)
        assert.equal(err.url, 'https://example.test/x')
        return true
      },
    )
  })

  it('a host missing httpFetch entirely surfaces a FetchError (never a silent success)', async () => {
    const bindings = await loadDiagnosticBindings()
    const host = baseHost() // no httpFetch method at all
    await assert.rejects(() =>
      bindings.__testHttpFetch(host, { method: 'GET', url: 'https://example.test/x', headers: {} }),
    )
  })
})

/**
 * Regression tests for a code-review finding on this PR:
 * `js_result_to_http_response` (crates/vaultkeeper-wasm/src/wasm_impl.rs)
 * originally accepted malformed `httpFetch()` results — `status` was cast
 * directly to `u16` (silently truncating/wrapping out-of-range or fractional
 * values), a missing/non-object `headers` silently became an empty list, and
 * a non-`Uint8Array` `body` was constructed blind (risking a JS-side throw or
 * a misleading coercion). Each case here must now reject with a typed
 * `FetchError` rather than silently producing a misleading `HttpResponse`.
 */
describe('__testHttpFetch — rejects malformed httpFetch() result shapes', () => {
  async function expectFetchError(response: unknown): Promise<void> {
    const bindings = await loadDiagnosticBindings()
    const host = { ...baseHost(), httpFetch: () => Promise.resolve(response) }
    await assert.rejects(
      () =>
        bindings.__testHttpFetch(host, {
          method: 'GET',
          url: 'https://example.test/x',
          headers: {},
        }),
      (thrown: unknown) => {
        assert.ok(isBridgeErrorShape(thrown))
        const err = mapWasmError(thrown)
        assert.ok(err instanceof FetchError, `expected FetchError, got ${err.constructor.name}`)
        return true
      },
    )
  }

  it('rejects a negative status instead of wrapping it into an in-range u16', async () => {
    await expectFetchError({ status: -1, headers: {}, body: new Uint8Array() })
  })

  it('rejects a status above u16::MAX instead of truncating it', async () => {
    await expectFetchError({ status: 70000, headers: {}, body: new Uint8Array() })
  })

  it('rejects a fractional status', async () => {
    await expectFetchError({ status: 200.5, headers: {}, body: new Uint8Array() })
  })

  it('rejects a missing headers field instead of defaulting to an empty list', async () => {
    await expectFetchError({ status: 200, body: new Uint8Array() })
  })

  it('rejects a non-object headers field (e.g. a string)', async () => {
    await expectFetchError({ status: 200, headers: 'not-an-object', body: new Uint8Array() })
  })

  it('rejects a headers object with a non-string value', async () => {
    await expectFetchError({ status: 200, headers: { 'x-count': 5 }, body: new Uint8Array() })
  })

  it('rejects a missing body field instead of coercing it to an empty array', async () => {
    await expectFetchError({ status: 200, headers: {} })
  })

  it('rejects a non-Uint8Array body (e.g. a plain string)', async () => {
    await expectFetchError({ status: 200, headers: {}, body: 'not-bytes' })
  })

  it('still accepts a well-formed result (control case)', async () => {
    const bindings = await loadDiagnosticBindings()
    const host = {
      ...baseHost(),
      httpFetch: () =>
        Promise.resolve({
          status: 200,
          headers: { 'x-ok': 'yes' },
          body: new Uint8Array([1, 2, 3]),
        }),
    }
    const result = await bindings.__testHttpFetch(host, {
      method: 'GET',
      url: 'https://example.test/x',
      headers: {},
    })
    assertDiagnosticHttpResponse(result)
    assert.equal(result.status, 200)
    assert.equal(result.headers['x-ok'], 'yes')
    assert.deepEqual([...result.body], [1, 2, 3])
  })
})

// ---------------------------------------------------------------------------
// AC3: prompt_approval — optional, fails closed
// ---------------------------------------------------------------------------

describe('__testPromptApproval — optional host capability, fail-closed (issue #239 AC3)', () => {
  it('a host without promptApproval fails closed (false), not an error', async () => {
    const bindings = await loadDiagnosticBindings()
    const host = baseHost() // no promptApproval
    const approved = await bindings.__testPromptApproval(
      host,
      'delegated-fetch',
      'GET https://example.test',
    )
    assert.equal(approved, false)
  })

  it('a host that implements promptApproval and approves returns true', async () => {
    const bindings = await loadDiagnosticBindings()
    const host = {
      ...baseHost(),
      promptApproval: (context: { action: string; detail: string }) => {
        assert.equal(context.action, 'delegated-fetch')
        assert.equal(context.detail, 'GET https://example.test')
        return Promise.resolve(true)
      },
    }
    const approved = await bindings.__testPromptApproval(
      host,
      'delegated-fetch',
      'GET https://example.test',
    )
    assert.equal(approved, true)
  })

  it('a host that implements promptApproval and declines returns false', async () => {
    const bindings = await loadDiagnosticBindings()
    const host = { ...baseHost(), promptApproval: () => Promise.resolve(false) }
    const approved = await bindings.__testPromptApproval(host, 'delegated-fetch', 'detail')
    assert.equal(approved, false)
  })
})

// ---------------------------------------------------------------------------
// AC5: JsSecretBackend scaffold
// ---------------------------------------------------------------------------

/** An in-memory `HostSecretBackend` mock (see `../types.ts`). */
function createMockSecretBackend(options?: { withList?: boolean }): {
  type: string
  displayName: string
  isAvailable: () => Promise<boolean>
  store: (id: string, secret: Uint8Array) => Promise<void>
  retrieve: (id: string) => Promise<Uint8Array>
  delete: (id: string) => Promise<void>
  exists: (id: string) => Promise<boolean>
  list?: () => Promise<string[]>
} {
  const store = new Map<string, Uint8Array>()
  const backend = {
    type: 'mock-backend',
    displayName: 'Mock Backend',
    isAvailable: () => Promise.resolve(true),
    store: (id: string, secret: Uint8Array) => {
      store.set(id, secret)
      return Promise.resolve()
    },
    retrieve: (id: string) => {
      const value = store.get(id)
      if (value === undefined) return Promise.reject(new Error(`not found: ${id}`))
      return Promise.resolve(value)
    },
    delete: (id: string) => {
      store.delete(id)
      return Promise.resolve()
    },
    exists: (id: string) => Promise.resolve(store.has(id)),
  }
  if (options?.withList !== false) {
    return { ...backend, list: () => Promise.resolve([...store.keys()]) }
  }
  return backend
}

describe('JsSecretBackend scaffold — store/retrieve/delete/exists/list (issue #239 AC5)', () => {
  it('reads type/displayName once at construction', async () => {
    const bindings = await loadDiagnosticBindings()
    const meta = bindings.__testJsSecretBackendMeta(createMockSecretBackend())
    assert.deepEqual(meta, { type: 'mock-backend', displayName: 'Mock Backend' })
  })

  it('isAvailable() reflects the JS mock', async () => {
    const bindings = await loadDiagnosticBindings()
    const available = await bindings.__testJsSecretBackendIsAvailable(createMockSecretBackend())
    assert.equal(available, true)
  })

  it('store/retrieve/exists/delete round-trip a secret through Uint8Array at the boundary', async () => {
    const bindings = await loadDiagnosticBindings()
    const backend = createMockSecretBackend()
    await bindings.__testJsSecretBackendStore(backend, 'my-id', 'my-secret-value')
    assert.equal(await bindings.__testJsSecretBackendExists(backend, 'my-id'), true)
    assert.equal(await bindings.__testJsSecretBackendRetrieve(backend, 'my-id'), 'my-secret-value')
    await bindings.__testJsSecretBackendDelete(backend, 'my-id')
    assert.equal(await bindings.__testJsSecretBackendExists(backend, 'my-id'), false)
  })

  it('list() returns every stored id when the mock implements list()', async () => {
    const bindings = await loadDiagnosticBindings()
    const backend = createMockSecretBackend()
    await bindings.__testJsSecretBackendStore(backend, 'a', 'va')
    await bindings.__testJsSecretBackendStore(backend, 'b', 'vb')
    const ids = await bindings.__testJsSecretBackendList(backend)
    assert.deepEqual([...ids].sort(), ['a', 'b'])
  })

  it('list() rejects with a typed NotCapableError when the mock omits list()', async () => {
    const bindings = await loadDiagnosticBindings()
    const backend = createMockSecretBackend({ withList: false })
    await assert.rejects(
      () => bindings.__testJsSecretBackendList(backend),
      (thrown: unknown) => {
        assert.ok(isBridgeErrorShape(thrown))
        const err = mapWasmError(thrown)
        assert.ok(
          err instanceof NotCapableError,
          `expected NotCapableError, got ${err.constructor.name}`,
        )
        assert.equal(err.backendType, 'mock-backend')
        assert.equal(err.capability, 'list')
        return true
      },
    )
  })

  it('retrieve() of a missing id propagates the JS rejection as an error', async () => {
    const bindings = await loadDiagnosticBindings()
    const backend = createMockSecretBackend()
    await assert.rejects(() => bindings.__testJsSecretBackendRetrieve(backend, 'does-not-exist'))
  })
})

/**
 * Regression tests for code-review findings on this PR: `JsSecretBackend`
 * (crates/vaultkeeper-wasm/src/wasm_impl.rs) originally coerced host-callback
 * results too leniently — `retrieve()` handed a possibly non-`Uint8Array`
 * result blind to `Uint8Array::new`, `exists()` defaulted any non-boolean
 * result to `false` via `unwrap_or`, and `list()` handed a possibly
 * non-array result blind to `js_sys::Array::from` and silently dropped
 * non-string entries. Each of these host-contract violations must now
 * surface as an error rather than silently producing misleading data (or
 * crashing on an uncaught JS exception).
 */
describe('JsSecretBackend scaffold — rejects malformed host-callback results', () => {
  function baseSecretBackendFields(): { type: string; displayName: string } {
    return { type: 'malformed-backend', displayName: 'Malformed Backend' }
  }

  it('retrieve() rejects a non-Uint8Array result instead of coercing it', async () => {
    const bindings = await loadDiagnosticBindings()
    const backend: HostSecretBackend = {
      ...baseSecretBackendFields(),
      isAvailable: () => Promise.resolve(true),
      store: () => Promise.resolve(),
      // @ts-expect-error -- deliberately violating the HostSecretBackend contract to test the Rust-side guard
      retrieve: () => Promise.resolve('not-a-uint8array'),
      delete: () => Promise.resolve(),
      exists: () => Promise.resolve(true),
    }
    await assert.rejects(() => bindings.__testJsSecretBackendRetrieve(backend, 'id'))
  })

  it('exists() rejects a non-boolean result instead of defaulting to false', async () => {
    const bindings = await loadDiagnosticBindings()
    const backend: HostSecretBackend = {
      ...baseSecretBackendFields(),
      isAvailable: () => Promise.resolve(true),
      store: () => Promise.resolve(),
      retrieve: () => Promise.resolve(new Uint8Array()),
      delete: () => Promise.resolve(),
      // @ts-expect-error -- deliberately violating the HostSecretBackend contract to test the Rust-side guard
      exists: () => Promise.resolve('true'),
    }
    await assert.rejects(() => bindings.__testJsSecretBackendExists(backend, 'id'))
  })

  it('list() rejects a non-array result instead of throwing or silently returning []', async () => {
    const bindings = await loadDiagnosticBindings()
    const backend: HostSecretBackend = {
      ...baseSecretBackendFields(),
      isAvailable: () => Promise.resolve(true),
      store: () => Promise.resolve(),
      retrieve: () => Promise.resolve(new Uint8Array()),
      delete: () => Promise.resolve(),
      exists: () => Promise.resolve(true),
      // @ts-expect-error -- deliberately violating the HostSecretBackend contract to test the Rust-side guard
      list: () => Promise.resolve(42),
    }
    await assert.rejects(() => bindings.__testJsSecretBackendList(backend))
  })

  it('list() rejects an array containing a non-string entry instead of silently dropping it', async () => {
    const bindings = await loadDiagnosticBindings()
    const backend: HostSecretBackend = {
      ...baseSecretBackendFields(),
      isAvailable: () => Promise.resolve(true),
      store: () => Promise.resolve(),
      retrieve: () => Promise.resolve(new Uint8Array()),
      delete: () => Promise.resolve(),
      exists: () => Promise.resolve(true),
      // @ts-expect-error -- deliberately violating the HostSecretBackend contract (list() must resolve string[]) to test the Rust-side guard
      list: () => Promise.resolve(['good-id', 42, 'other-good-id']),
    }
    await assert.rejects(() => bindings.__testJsSecretBackendList(backend))
  })
})

describe('__testHttpFetch — rejects a malformed request.body (js_value_to_http_request)', () => {
  it('rejects a non-Uint8Array request.body instead of coercing it', async () => {
    const bindings = await loadDiagnosticBindings()
    const host = {
      ...baseHost(),
      httpFetch: () => Promise.reject(new Error('should not be called')),
    }
    await assert.rejects(() =>
      bindings.__testHttpFetch(host, {
        method: 'GET',
        url: 'https://example.test/x',
        headers: {},
        body: 'not-bytes',
      }),
    )
  })
})

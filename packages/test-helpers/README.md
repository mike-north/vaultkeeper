# @vaultkeeper/test-helpers

Test utilities for consumers of [vaultkeeper](https://www.npmjs.com/package/vaultkeeper):
an in-memory backend and a pre-configured `TestVault` for fast, hermetic tests with zero OS
dependencies.

## Installation

```sh
pnpm add -D @vaultkeeper/test-helpers
```

**Requirements:** Node >= 20

## Quick start

```ts
import { TestVault } from '@vaultkeeper/test-helpers'

const { keeper, backend } = await TestVault.create()
await backend.store('MY_SECRET', 'hunter2')

// `keeper.setup()` requires an explicit executable-trust choice; tests use the
// development-only `skipTrust` opt-out to stay hermetic. (The `TestVault.setup()`
// convenience method applies this default for you — via a `TestVault` instance
// from `TestVault.create()`, e.g. `testVault.setup('MY_SECRET')` with no options.)
//
// WARNING: this test-only default does NOT apply to the real `VaultKeeper.setup()`
// in the `vaultkeeper` package. There, setup() has no default and always requires
// either `executablePath` (TOFU verification) or an explicit `{ skipTrust: true }`
// — a bare `setup('MY_SECRET')` throws `ExecutableTrustRequiredError`. Don't copy a
// zero-arg setup() out of a test into non-test production code.
const jwe = await keeper.setup('MY_SECRET', { skipTrust: true })
const { token } = await keeper.authorize(jwe)
const { result } = await keeper.exec(token, {
  command: 'echo',
  args: ['done'],
  env: { SECRET: '{{secret}}' },
})
```

`TestVault` wraps a real `VaultKeeper` backed by `InMemoryBackend` — no OS keychain, no
filesystem, no doctor preflight checks. Use `InMemoryBackend` directly if you need a bare backend
without the pre-configured vault.

## Full documentation

See the [repository README](https://github.com/mike-north/vaultkeeper#readme) for the full
`vaultkeeper` API this package is built to test against.

## License

MIT

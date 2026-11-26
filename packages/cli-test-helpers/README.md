# @vaultkeeper/cli-test-helpers

CLI test harness for [@vaultkeeper/cli](https://www.npmjs.com/package/@vaultkeeper/cli) consumers:
spins up an isolated temp config directory with a file backend and runs the CLI binary as a
subprocess.

## Installation

```sh
pnpm add -D @vaultkeeper/cli-test-helpers
```

**Requirements:** Node >= 20

## Quick start

```ts
import { expect, it } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'

it('stores a secret and passes doctor checks', async () => {
  const env = await createCliTestEnv()

  try {
    const stored = await env.runWithStdin(['store', '--name', 'MY_SECRET'], 'hunter2')
    expect(stored.exitCode).toBe(0)

    const result = await env.run(['doctor'])
    expect(result.exitCode).toBe(0)
  } finally {
    await env.cleanup()
  }
})
```

Each `createCliTestEnv()` call produces its own isolated `configDir` — tests can run in parallel
without interfering with each other or the host machine's real vaultkeeper config.

## Full documentation

See the [repository README](https://github.com/mike-north/vaultkeeper#readme) for the CLI command
reference this harness exercises.

## License

MIT

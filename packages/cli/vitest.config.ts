import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Type-level tests (issue #199): `*.test-d.ts` files are compiled with the
    // real TypeScript program (NodeNext resolution, same strict options as the
    // build), mirroring packages/vaultkeeper/vitest.config.ts.
    typecheck: {
      enabled: true,
      tsconfig: './tsconfig.test-d.json',
      include: ['test/**/*.test-d.ts'],
    },
    coverage: {
      provider: 'v8',
    },
  },
})

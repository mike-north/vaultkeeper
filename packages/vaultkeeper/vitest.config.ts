import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    passWithNoTests: true,
    // Type-level tests (issue #193): `*.test-d.ts` files are compiled with the
    // real TypeScript program (NodeNext resolution, same strict options as the
    // build) so `SetupOptions`' trust-choice XOR is enforced at the type level.
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

import { defineConfig } from 'tsup'

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    treeshake: true,
  },
  {
    entry: ['src/backend/one-password-worker.ts'],
    format: ['esm'],
    dts: false,
    sourcemap: true,
    clean: false,
    treeshake: true,
  },
])

import eslint from '@eslint/js'
import tseslint from 'typescript-eslint'
import prettierConfig from 'eslint-config-prettier'
import nodePlugin from 'eslint-plugin-n'
import securityPlugin from 'eslint-plugin-security'

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        project: ['./packages/*/tsconfig.json', './packages/*/tsconfig.test.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      n: nodePlugin,
      security: securityPlugin,
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
        },
      ],
      'no-plusplus': 'off',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unsafe-argument': 'error',
      '@typescript-eslint/no-unsafe-assignment': 'error',
      '@typescript-eslint/no-unsafe-call': 'error',
      '@typescript-eslint/no-unsafe-member-access': 'error',
      '@typescript-eslint/no-unsafe-return': 'error',
      '@typescript-eslint/consistent-type-assertions': [
        'error',
        {
          assertionStyle: 'never',
        },
      ],
      'n/no-unsupported-features/node-builtins': 'error',
      'n/no-deprecated-api': 'error',
      'security/detect-object-injection': 'warn',
      'security/detect-non-literal-fs-filename': 'off',
      'security/detect-non-literal-require': 'error',
      'security/detect-possible-timing-attacks': 'warn',
    },
  },
  prettierConfig,
  {
    files: ['**/test/**', '**/*.test.ts', '**/*.spec.ts'],
    rules: {
      'security/detect-object-injection': 'off',
    },
  },
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/coverage/**',
      '**/tsup.config.ts',
      '**/vitest.config.ts',
      'vitest.workspace.ts',
      'eslint.config.ts',
      'prettier.config.js',
      '**/scratch/**',
      '**/tmp/**',
    ],
  },
)

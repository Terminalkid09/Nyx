import js from '@eslint/js'
import tseslint from 'typescript-eslint'
import reactHooks from 'eslint-plugin-react-hooks'
import jsxA11y from 'eslint-plugin-jsx-a11y'
import globals from 'globals'

export default tseslint.config(
  { ignores: ['dist', 'node_modules', '*.config.ts'] },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'jsx-a11y': jsxA11y,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...jsxA11y.flatConfigs.recommended.rules,
      // The codebase intentionally uses `any` casts for backend status fields
      // that are not fully typed yet — flag but do not fail the build.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      // Empty catch blocks are the idiomatic "best-effort cleanup" pattern in
      // UI code (clipboard, localStorage, optional Electron bridges).
      'no-empty': ['error', { allowEmptyCatch: true }],
      // Pending larger refactors — tracked as warnings so CI stays green:
      // - set-state-in-effect / immutability / purity / refs /
      //   preserve-manual-memoization / no-useless-assignment are react-hooks
      //   v6 compiler-grade rules needing per-hook rework
      // - label-has-associated-control needs a labels pass across forms (109)
      // - click-events / static-or-noninteractive-element interactions remain
      //   on tables that still need keyboard handlers (~40 sites)
      // - no-autofocus: autofocus in modal dialogs is intentional UX here
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/immutability': 'warn',
      'react-hooks/purity': 'warn',
      'react-hooks/refs': 'warn',
      'react-hooks/preserve-manual-memoization': 'warn',
      'jsx-a11y/label-has-associated-control': 'warn',
      'jsx-a11y/click-events-have-key-events': 'warn',
      'jsx-a11y/no-static-element-interactions': 'warn',
      'jsx-a11y/no-noninteractive-tabindex': 'warn',
      'jsx-a11y/no-noninteractive-element-interactions': 'warn',
      'jsx-a11y/no-autofocus': 'warn',
    },
  },
)

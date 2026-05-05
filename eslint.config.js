import js from "@eslint/js";
import globals from "globals";
import { defineConfig } from "eslint/config";
import jest from "eslint-plugin-jest";

export default defineConfig([
  // ✅ Base config (for all JS files)
  {
    files: ["**/*.{js,mjs,cjs}"],
    plugins: { js },
    extends: ["js/recommended"],
    languageOptions: {
      globals: globals.node,
    },
  },

  // ✅ Jest config (ONLY for test files)
  {
    files: ["tests/**/*.js"],
    plugins: { jest },
    languageOptions: {
      globals: {
        ...globals.node,
        ...jest.environments.globals.globals,
      },
    },
    rules: {
      ...jest.configs.recommended.rules,
    },
  },
]);
